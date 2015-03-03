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
#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dislocker.h"

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
static int xopen_file(const char* file, int flags, mode_t mode)
{
	int fd = -1;
	
	xprintf(L_DEBUG, "Trying to open '%s'... ", file);
	
	if((fd = open(file, flags, mode)) < 0)
	{
		char* err_string = NULL;
		size_t arbitrary_value = 42;
		char* before = "Failed to open file";
		char* after = xmalloc(arbitrary_value);
		
		snprintf(after, arbitrary_value, "%s", file);
		
		if(arbitrary_value < strlen(file))
		{
			after[arbitrary_value-4] = '.';
			after[arbitrary_value-3] = '.';
			after[arbitrary_value-2] = '.';
		}
		
		size_t len = strlen(before);
		
		err_string = xmalloc(len + arbitrary_value + 4);
		snprintf(err_string, len + arbitrary_value + 4, "%s '%s'", before, after);
		
		xfree(after);
		
		xperror(err_string);
	}
	
	xprintf(L_DEBUG, "Opened (fd #%d).\n", fd);
	
	return fd;
}



static int file_main(char* ntfs_file, dis_context_t* dis_ctx)
{
	// Check parameter
	if(!ntfs_file)
	{
		xprintf(L_ERROR, "Error, empty string file. Abort.\n");
		return EXIT_FAILURE;
	}
	
	if(!dis_ctx)
	{
		xprintf(L_ERROR, "Error, no context given. Abort.\n");
		return EXIT_FAILURE;
	}
	
	dis_iodata_t io_data = dis_ctx->io_data;
	size_t buf_size = (size_t)(NB_READ_SECTOR * io_data.sector_size);
	uint8_t* buffer = xmalloc(buf_size);
	
	mode_t mode = S_IRUSR|S_IWUSR;
	if(dis_ctx->cfg.flags & DIS_FLAG_READ_ONLY)
		mode = S_IRUSR;
	
	int fd_ntfs = xopen_file(ntfs_file, O_CREAT|O_RDWR|O_LARGEFILE, mode);
	
	
	off_t offset          = 0;
	long long int percent = 0;
	
	xprintf(L_INFO, "File size: %llu bytes\n", io_data.volume_size);
	
	/* Read all sectors and decrypt them if necessary */
	xprintf(L_INFO, "\rDecrypting... 0%%");
	fflush(stdout);
	
	off_t decrypting_size = (off_t)io_data.volume_size;
	
	while(offset < decrypting_size)
	{
		/* Read and decrypt an entire region of the disk */
		dislock(dis_ctx, buffer, offset, buf_size);
		
		offset += (off_t) buf_size;
		
		
		/* Now copy the required amount of data to the user file */
		xwrite(fd_ntfs, buffer, buf_size);
		
		/* Screen update */
		if(percent != (offset*100)/decrypting_size)
		{
			percent = (offset*100)/decrypting_size;
			xprintf(L_INFO, "\rDecrypting... %lld%%", percent);
			fflush(stdout);
		}
	}
	
	xprintf(L_INFO, "\rDecrypting... Done.\n");
	
	xfree(buffer);
	xclose(fd_ntfs);
	
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
	
	dis_context_t* dis_ctx = dis_new();
	
	
	/* Get command line options */
	param_idx = dis_getopts(&dis_ctx->cfg, argc, argv);
	
	/* Check that we have the file where to put NTFS data */
	if(param_idx >= argc || param_idx <= 0)
	{
		fprintf(stderr, "Error, no file given. Abort.\n");
		return EXIT_FAILURE;
	}
	
	/* Initialize dislocker */
	if(dis_initialize(dis_ctx) == EXIT_FAILURE)
	{
		xprintf(L_CRITICAL, "Can't initialize dislocker. Abort.\n");
		return EXIT_FAILURE;
	}
	
	/*
	 * Create a NTFS file which could be mounted using `mount -o loop...`
	 */
	char* ntfs_file = argv[param_idx];
	
	// Check if the file exists, we don't want to overwrite it
	if(access(ntfs_file, F_OK) == 0)
	{
		xprintf(L_CRITICAL, "'%s' already exists, can't override. Abort.\n", ntfs_file);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	xprintf(L_INFO, "Putting NTFS data into '%s'...\n", ntfs_file);
	
	// TODO before running the encryption, check if the NTFS file will fit into the free space
	
	/* Run the decryption */
	ret = file_main(ntfs_file, dis_ctx);
	
	dis_destroy(dis_ctx);
	
	return ret;
}
