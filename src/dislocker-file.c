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

/* This define is for the O_LARGEFILE definition */
#define _GNU_SOURCE 1

#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dislocker/xstd/xstdio.h"
#include "dislocker/xstd/xstdlib.h"
#include "dislocker/inouts/inouts.h"
#include "dislocker/config.h"
#include "dislocker/common.h"
#include "dislocker/dislocker.h"

#if defined(__DARWIN) || defined(__FREEBSD)
#  define O_LARGEFILE 0
#endif /* __DARWIN || __FREEBSD */


/* Number of sectors we're reading at a time */
#define NB_READ_SECTOR 16



/**
 * open(2) syscall wrapper (for the one with mode)
 *
 * @param file The file (with its path) to open
 * @param flags The mode(s) along the opening (read/write/...)
 * @param mode The mode(s) a file will have if created
 * @return The file descriptor returned by the actual open
 */
static int dis_open_file(const char* file, int flags, mode_t mode)
{
	int fd = -1;

	dis_printf(L_DEBUG, "Trying to open '%s'... ", file);

	if((fd = open(file, flags, mode)) < 0)
	{
#define DIS_FILE_OPEN_FAIL_STR "Failed to open file"
#define DIS_FILE_OPEN_FAIL_LEN sizeof(DIS_FILE_OPEN_FAIL_STR)
		size_t len = DIS_FILE_OPEN_FAIL_LEN + strlen(file) + 4;
		char* err_string = dis_malloc(len);

		snprintf(err_string, len , "%s '%s'", DIS_FILE_OPEN_FAIL_STR, file);

		perror(err_string);
		dis_free(err_string);
		exit(2);
	}

	dis_printf(L_DEBUG, "Opened (fd #%d).\n", fd);

	return fd;
}



static int file_main(char* ntfs_file, dis_context_t dis_ctx)
{
	// Check parameter
	if(!ntfs_file)
	{
		dis_printf(L_ERROR, "Error, empty string file. Abort.\n");
		return EXIT_FAILURE;
	}

	if(!dis_ctx)
	{
		dis_printf(L_ERROR, "Error, no context given. Abort.\n");
		return EXIT_FAILURE;
	}

	size_t buf_size = (size_t)(NB_READ_SECTOR * dis_inouts_sector_size(dis_ctx));
	uint8_t* buffer = dis_malloc(buf_size);

	mode_t mode = S_IRUSR|S_IWUSR;
	if(dis_is_read_only(dis_ctx))
		mode = S_IRUSR;

	int fd_ntfs = dis_open_file(ntfs_file, O_CREAT|O_RDWR|O_LARGEFILE, mode);


	off_t offset          = 0;
	long long int percent = 0;
	off_t decrypting_size = (off_t)dis_inouts_volume_size(dis_ctx);

	dis_printf(L_INFO, "File size: %" PRIu64 " bytes\n", decrypting_size);

	/* Read all sectors and decrypt them if necessary */
	dis_printf(L_INFO, "\rDecrypting... 0%%");
	fflush(stdout);

	while(offset < decrypting_size)
	{
		/* Read and decrypt an entire region of the disk */
		dislock(dis_ctx, buffer, offset, buf_size);

		offset += (off_t) buf_size;


		/* Now copy the required amount of data to the user file */
		dis_write(fd_ntfs, buffer, buf_size);

		/* Screen update */
		if(percent != (offset*100)/decrypting_size)
		{
			percent = (offset*100)/decrypting_size;
			dis_printf(L_INFO, "\rDecrypting... %lld%%", percent);
			fflush(stdout);
		}
	}

	dis_printf(L_INFO, "\rDecrypting... Done.\n");

	dis_free(buffer);
	dis_close(fd_ntfs);

	return EXIT_SUCCESS;
}




/**
 * Main function ran initially
 */
int main(int argc, char** argv)
{
	// Check parameters number
	if(argc < 2)
	{
		dis_usage();
		exit(EXIT_FAILURE);
	}

	int param_idx = 0;
	int ret       = 0;

	dis_context_t dis_ctx = dis_new();


	/* Get command line options */
	param_idx = dis_getopts(dis_ctx, argc, argv);

	/* Initialize dislocker */
	if(dis_initialize(dis_ctx) == EXIT_FAILURE)
	{
		dis_printf(L_CRITICAL, "Can't initialize dislocker. Abort.\n");
		return EXIT_FAILURE;
	}

	/* Check that we have the file where to put NTFS data */
	if(param_idx >= argc || param_idx <= 0)
	{
		dis_printf(L_CRITICAL, "Error, no file given. Abort.\n");
		return EXIT_FAILURE;
	}

	/*
	 * Create a NTFS file which could be mounted using `mount -o loop...`
	 */
	char* ntfs_file = argv[param_idx];

	// Check if the file exists, we don't want to overwrite it
	if(access(ntfs_file, F_OK) == 0)
	{
		dis_printf(L_CRITICAL, "'%s' already exists, can't override. Abort.\n", ntfs_file);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}

	dis_printf(L_INFO, "Putting NTFS data into '%s'...\n", ntfs_file);

	// TODO before running the encryption, check if the NTFS file will fit into the free space

	/* Run the decryption */
	ret = file_main(ntfs_file, dis_ctx);

	dis_destroy(dis_ctx);

	return ret;
}
