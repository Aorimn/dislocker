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
 * Testing BEK files reading and parsing
 */

#include <getopt.h>

#include "common.h"
#include "read_bekfile.h"


void usage(char* prog) 
{
	fprintf(stderr, "usage: %s [-h] [-f file.bek]\n", prog);
	exit(1);
}


int main (int argc, char **argv)
{
	char *filename = NULL;
	int c  = 0;
	int fd = 0;
	
	dataset_t bek_dataset;
	external_info_header_t header;
	key_header_t key_header;
	
	opterr = 0;
	
	while((c = getopt (argc, argv, "hf:")) != -1)
		switch(c)
		{
			case 'h':
				usage(argv[0]);
				break;
			case 'f':
				filename = optarg;
				break;
			case '?':
				if (optopt == 'f')
					fprintf (stderr, "Option -%c requires a filename.\n", optopt);
				else
					fprintf (stderr, "Unknown option character '\\x%x'.\n", optopt);
				return EXIT_FAILURE;
			default:
				usage(argv[0]);
		}
	
	xstdio_init(L_INFO, NULL);
	
	if(filename == NULL) 
	{
		xprintf(L_CRITICAL, "Filename must be provided\n");
		usage(argv[0]);
	}
	
	if(( fd = open(filename, O_RDONLY) ) < 0) 
	{
		xprintf(L_CRITICAL, "Failed to open file %s\n", filename);
		exit(1);
	}
	
	decode(fd, &bek_dataset, &header, &key_header);
	
	close(fd);
	
	/* display infos */
	xprintf(L_INFO, "BEK File Information: %s\n", filename);
	
	/* bek header */
	print_bek_header(&bek_dataset);
	
	/* header */
	print_ext_info_header(&header);
	
	/* key header and payload */
	print_key(&key_header);
	
	xstdio_end();
	
	return EXIT_SUCCESS;
}

