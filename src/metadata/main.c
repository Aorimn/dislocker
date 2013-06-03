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
/*
 * Get and display BitLocker's metadata
 */

#define _GNU_SOURCE

#include <getopt.h>

#include <locale.h>


#include "common.h"
#include "config.h"
#include "metadata.h"


void usage()
{
	fprintf(stderr, "Usage: "PROGNAME" [-h] [-V VOLUME]\n"
					"\n"
					"    -h         print this help and exit\n"
					"    -o         partition offset\n"
					"    -V VOLUME  volume to get metadata from\n"
		   );
}



int main(int argc, char **argv)
{
	if(argc < 2)
	{
		usage();
		exit(1);
	}
	
	int optchar = 0;
	char *volume_path = NULL;
	
	int fd = 0;
	volume_header_t volume_header;
	
	void* bl_metadata = NULL;
	
	bitlocker_dataset_t* dataset = NULL;
	datum_vmk_t* vmk_clear_key_datum = NULL;
	
	dis_config_t cfg;
	memset(&cfg, 0, sizeof(cfg));
	
	while((optchar = getopt(argc, argv, "o:V:h")) != -1)
	{
		switch(optchar)
		{
			case 'h':
				usage();
				return 0;
			case 'o':
				cfg.offset = (off_t) strtoll(optarg, NULL, 10);
				break;
			case 'V':
				volume_path = strdup(optarg);
				break;
			case '?':
			default:
				fprintf(stderr, "Unknown option encountered.\n");
				usage();
				exit(1);
		}
	}
	
	xstdio_init(L_INFO, NULL);
	
	if(!volume_path)
	{
		usage();
		exit(1);
	}
	
	// Open the volume as a normal file
	fd = xopen(volume_path, O_RDONLY|O_LARGEFILE);
	
	
	/* To print UTF-32 strings */
	setlocale(LC_ALL, "");
	
	
	// Initialize structures
	memset(&volume_header, 0, sizeof(volume_header_t));
	
	
	// Getting volume infos
	if(!get_volume_header(&volume_header, fd, cfg.offset))
		xprintf(L_ERROR, "Error during reading the volume: not enough byte read.\n");
	
	// Printing them
	print_volume_header(L_INFO, &volume_header);
	
	
	// Getting BitLocker metadata and validate them
	if(!get_metadata_check_validations(&volume_header, fd, &bl_metadata, &cfg))
	{
		xprintf(L_CRITICAL, "A problem occured during the retrieving of metadata. Abort.\n");
		exit(1);
	}
	
	if(cfg.force_block == 0 || !bl_metadata)
	{
		xprintf(L_CRITICAL, "Can't find a valid set of metadata on the disk. Abort.\n");
		exit(EXIT_FAILURE);
	}
	
	// Printing BitLocker metadata
	print_bl_metadata(L_INFO, bl_metadata);
	xprintf(L_INFO, "\n");
	
	
	// Now we're looking at the data
	print_data(L_INFO, bl_metadata);
	
	
	// Get the metadata's dataset
	if(!get_dataset(bl_metadata, &dataset))
	{
		xprintf(L_CRITICAL, "Can't find a valid dataset. Abort.\n");
		exit(1);
	}
	
	// Search for a clear key
	if(has_clear_key(dataset, &vmk_clear_key_datum))
	{
		xprintf(L_INFO, "\n===== There's a clear key here!\n===== Take a look at it:\n");
		print_one_datum(L_INFO, (void*)vmk_clear_key_datum);
		xprintf(L_INFO, "============[ Clear key end ]============\n");
	}
	else
		xprintf(L_INFO, "No clear key found.\n");
	
	
	
	// Do some cleaning stuff
	if(volume_path)
		xfree(volume_path);
	
	if(bl_metadata)
		xfree(bl_metadata);
	
	xclose(fd);
	xstdio_end();
	
	return EXIT_SUCCESS;
}
