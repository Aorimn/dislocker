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

#include "dislocker.h"

#if defined(__DARWIN) || defined(__FREEBSD)
#  define O_LARGEFILE 0
#endif /* __DARWIN || __FREEBSD */


/* Number of sectors we're reading at a time */
#define NB_READ_SECTOR 16



int file_main(char* ntfs_file, dis_context_t* dis_ctx)
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
	if(dis_ctx->cfg.is_ro & READ_ONLY)
		mode = S_IRUSR;
	
	int fd_ntfs = xopen2(ntfs_file, O_CREAT|O_RDWR|O_LARGEFILE, mode);
	
	
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
	
	dis_context_t dis_ctx;
	memset(&dis_ctx, 0, sizeof(dis_context_t));
	
	
	/* Get command line options */
	param_idx = dis_parse_args(&dis_ctx.cfg, argc, argv);
	
	/* Check that we have the file where to put NTFS data */
	if(param_idx >= argc || param_idx <= 0)
	{
		fprintf(stderr, "Error, no file given. Abort.\n");
		return EXIT_FAILURE;
	}
	
	/* Initialize dislocker */
	if(dis_initialize(&dis_ctx) == EXIT_FAILURE)
	{
		xprintf(L_CRITICAL, "Can't initialize dislocker. Abort.\n");
		return EXIT_FAILURE;
	}
	
	/*
	 * Create a NTFS file which could be mounted using `mount -o loop...`
	 */
	
	char* ntfs_file = argv[param_idx];
	xprintf(L_INFO, "Putting NTFS data into '%s'...\n", ntfs_file);
	
	/* Run the decryption */
	ret = file_main(ntfs_file, &dis_ctx);
	
	dis_destroy(&dis_ctx);
	
	return ret;
}
