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
#include "metadata/print_metadata.h"
#include "metadata/metadata.h"
#include "accesses/bek/bekfile.h"


void usage(char* prog)
{
	fprintf(stderr, "usage: %s [-h] [-f file.bek]\n", prog);
}


int main (int argc, char **argv)
{
	char *filename = NULL;
	int c  = 0;
	int fd = 0;
	
	void* bek_dataset;
	
	opterr = 0;
	
	while((c = getopt (argc, argv, "hf:")) != -1)
		switch(c)
		{
			case 'h':
				usage(argv[0]);
				return EXIT_SUCCESS;
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
				return EXIT_FAILURE;
		}
	
	xstdio_init(L_INFO, NULL);
	
	if(filename == NULL) 
	{
		xprintf(L_CRITICAL, "Filename must be provided\n");
		usage(argv[0]);
		return EXIT_FAILURE;
	}
	
	if(( fd = open(filename, O_RDONLY) ) < 0) 
	{
		xprintf(L_CRITICAL, "Failed to open file %s\n", filename);
		return EXIT_FAILURE;
	}
	
	if(!get_bek_dataset(fd, &bek_dataset))
	{
		xprintf(L_CRITICAL, "Unable to get the dataset from the BEK file\n");
		return EXIT_FAILURE;
	}
	
	close(fd);
	
	/* display infos */
	xprintf(L_INFO, "BEK File Information: %s\n", filename);
	
	/* bek header */
	print_dataset(L_INFO, bek_dataset);
	
	/* external datum, which contains the decryption key */
	print_one_datum(L_INFO, bek_dataset + sizeof(bitlocker_dataset_t));
	
	xfree(bek_dataset);
	xstdio_end();
	
	return EXIT_SUCCESS;
}

