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


#define _GNU_SOURCE


#include "encommon.h"
#include "dislocker.h"
#include "encryption/decrypt.h"
#include "sectors.h"
#include "metadata/metadata.h"
#include "file.h"


#ifdef __DARWIN
#  define O_LARGEFILE 0
#endif /* __DARWIN */


int file_main(char* ntfs_file)
{
	// Check parameter
	if(!ntfs_file)
	{
		xprintf(L_ERROR, "Error, empty string file. Abort.\n");
		return EXIT_FAILURE;
	}
	
	
	/** @see encommon.h */
	uint8_t* buffer = xmalloc((size_t)(NB_READ_SECTOR * disk_op_data.sector_size));
	
	mode_t mode = S_IRUSR|S_IWUSR;
	if(disk_op_data.cfg->is_ro & READ_ONLY)
		mode = S_IRUSR;
	
	int fd_ntfs = xopen2(ntfs_file, O_CREAT|O_RDWR|O_LARGEFILE, mode);
	
	
	off_t offset          = 0;
	long long int percent = 0;
	
	xprintf(L_INFO, "File size: %llu bytes\n", disk_op_data.volume_size);
	
	/* Read all sectors and decrypt them if necessary */
	xprintf(L_INFO, "\rDecrypting... 0%%");
	fflush(stdout);
	
	off_t decrypting_size = (off_t)disk_op_data.volume_size;
	
	while(offset < decrypting_size)
	{
		/* Read and decrypt an entire region of the disk */
		disk_op_data.decrypt_region(
			disk_op_data.volume_fd, 
			NB_READ_SECTOR,
			disk_op_data.sector_size, 
			offset,
			buffer
		);
		
		offset += NB_READ_SECTOR * disk_op_data.sector_size;
		
		
		/* Now copy the required amount of data to the user file */
		xwrite(fd_ntfs, buffer, (size_t)(NB_READ_SECTOR * disk_op_data.sector_size));
		
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
