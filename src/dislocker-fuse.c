/* -*- coding: utf-8 -*- */
/* -*- mode: c -*- */
/*
 * Dislocker -- enables to read/write on BitLocker encrypted partitions under
 * Linux
 * Copyright (C) 2012-2013  Romain Coltel, Hervé Schauer Consultants
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */


#include <string.h>
#include <errno.h>

#include "dislocker/xstd/xstdio.h"
#include "dislocker/xstd/xstdlib.h"
#include "dislocker/return_values.h"
#include "dislocker/config.h"
#include "dislocker/dislocker.h"


# include <fuse.h>


/** NTFS virtual partition's name */
#define NTFS_FILENAME "dislocker-file"
#define NTFS_FILERELATIVEPATH "/" NTFS_FILENAME

#include "dislocker/inouts/inouts.h"
#include "dislocker/dislocker.h"
#include "dislocker/metadata/metadata.h"


/**
 * Data used globally for operation on disk (encryption/decryption) and in the
 * dislocker library.
 */
dis_context_t dis_ctx;


/**
 * Stubs used for FUSE operations.
 */
static int fs_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	if(!path || !stbuf)
		return -EINVAL;

	memset(stbuf, 0, sizeof(struct stat));
	if(strcmp(path, "/") == 0)
	{
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
	}
	else if(strcmp(path, NTFS_FILERELATIVEPATH) == 0)
	{
		mode_t m = dis_is_read_only(dis_ctx) ? 0444 : 0666;
		stbuf->st_mode = S_IFREG | m;
		stbuf->st_nlink = 1;
		stbuf->st_size = (off_t)dis_inouts_volume_size(dis_ctx);
	}
	else
		res = -ENOENT;

	return res;
}

static int fs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                      off_t offset, struct fuse_file_info *fi)
{
	/* Both variables aren't used here */
	(void) offset;
	(void) fi;

	if(!path || !buf || !filler)
		return -EINVAL;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, NTFS_FILENAME, NULL, 0);

	return 0;
}

static int fs_open(const char *path, struct fuse_file_info *fi)
{
	if(!path || !fi)
		return -EINVAL;

	if (strcmp(path, NTFS_FILERELATIVEPATH) != 0)
		return -ENOENT;


	if(dis_is_read_only(dis_ctx))
	{
		if((fi->flags & O_ACCMODE) != O_RDONLY)
			return -EACCES;
	}
	else
	{
		/* Authorize read/write, readonly and writeonly operations */
		if((fi->flags & O_ACCMODE) != O_RDWR   &&
		   (fi->flags & O_ACCMODE) != O_RDONLY &&
		   (fi->flags & O_ACCMODE) != O_WRONLY)
			return -EACCES;
	}

	return 0;
}

static int fs_read(
	const char *path,
	char *buf,
	size_t size,
	off_t offset,
	__attribute__ ((unused)) struct fuse_file_info *fi)
{
	if(!path || !buf)
		return -EINVAL;

	/*
	 * Perform basic checks
	 */
	if(strcmp(path, NTFS_FILERELATIVEPATH) != 0)
	{
		dis_printf(L_DEBUG, "Unknown entry requested: \"%s\"\n", path);
		return -ENOENT;
	}

	return dislock(dis_ctx, (uint8_t*) buf, offset, size);
}

static int fs_write(
	const char *path,
	const char *buf,
	size_t size,
	off_t offset,
	__attribute__ ((unused)) struct fuse_file_info *fi)
{
	// Check parameters
	if(!path || !buf)
		return -EINVAL;

	if(strcmp(path, NTFS_FILERELATIVEPATH) != 0)
	{
		dis_printf(L_DEBUG, "Unknown entry requested: \"%s\"\n", path);
		return -ENOENT;
	}

	return enlock(dis_ctx, (uint8_t*) buf, offset, size);
}


/* Structure used by the FUSE driver */
struct fuse_operations fs_oper = {
	.getattr = fs_getattr,
	.readdir = fs_readdir,
	.open    = fs_open,
	.read    = fs_read,
	.write   = fs_write,
};


/**
 * Main function ran initially
 */
int main(int argc, char** argv)
{
	char* volume_path = NULL;

	// Check parameters number
	if(argc < 2)
	{
		dis_usage();
		exit(EXIT_FAILURE);
	}

	int param_idx = 0;
	int ret       = EXIT_SUCCESS;

	/* Get command line options */
	dis_ctx = dis_new();
	param_idx = dis_getopts(dis_ctx, argc, argv);

	/*
	 * Check we have a volume path given and if not, take the first non-argument
	 * as the volume path
	 */
	dis_getopt(dis_ctx, DIS_OPT_VOLUME_PATH, (void**) &volume_path);
	if(volume_path == NULL)
	{
		if(param_idx >= argc || param_idx <= 0)
		{
			dis_printf(L_CRITICAL, "Error, no volume path given. Abort.\n");
			return EXIT_FAILURE;
		}

		dis_printf(L_DEBUG, "Setting the volume path to %s.\n", argv[param_idx]);
		dis_setopt(dis_ctx, DIS_OPT_VOLUME_PATH, argv[param_idx]);
		param_idx++;
	}

	/* Initialize dislocker */
	if(dis_initialize(dis_ctx) != DIS_RET_SUCCESS)
	{
		dis_printf(L_CRITICAL, "Can't initialize dislocker. Abort.\n");
		return EXIT_FAILURE;
	}

	/* Check we got enough arguments for at least one more, the mount point */
	if(param_idx >= argc || param_idx <= 0)
	{
		dis_printf(L_CRITICAL, "Error, no mount point given. Abort.\n");
		return EXIT_FAILURE;
	}


	/*
	 * Create the parameters table needed for FUSE and run it
	 * This is as we're running argv[0] followed by ARGS (see usage())
	 */
	/* Compute the new argc given to FUSE */
	size_t new_argc = (size_t)(argc - param_idx + 1);
	dis_printf(L_DEBUG, "New value for argc: %d\n", new_argc);

	char** new_argv = dis_malloc(new_argc * sizeof(char*));

	/* Get argv[0] */
	size_t lg = strlen(argv[0]) + 1;
	*new_argv = dis_malloc(lg);
	memcpy(*new_argv, argv[0], lg);

	/* Get all of the parameters from param_idx till the end */
	size_t loop = 0;
	for(loop = 1; loop < new_argc; ++loop)
	{
		lg = strlen(argv[(size_t)param_idx + loop - 1]) + 1;
		*(new_argv + loop) = dis_malloc(lg);
		memcpy(*(new_argv + loop), argv[(size_t)param_idx + loop - 1], lg);
	}


	dis_printf(L_INFO, "Running FUSE with these arguments: \n");
	for(loop = 0; loop < new_argc; ++loop)
		dis_printf(L_INFO, "  `--> '%s'\n", *(new_argv + loop));


	/* Run FUSE */
	ret = fuse_main((int)new_argc, new_argv, &fs_oper, NULL);

	/* Free FUSE params */
	for(loop = 0; loop < new_argc; ++loop)
		dis_free(new_argv[loop]);
	dis_free(new_argv);


	/* Destroy dislocker structures */
	dis_destroy(dis_ctx);

	return ret;
}
