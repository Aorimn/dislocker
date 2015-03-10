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

#include "dislocker/return_values.h"
#include "dislocker/dislocker.h"
#include "dislocker/metadata/print_metadata.h"


void usage()
{
	fprintf(stderr,
		"Usage: " PROGNAME " [-hov] [-V VOLUME]\n"
		"\n"
		"    -h         print this help and exit\n"
		"    -o         partition offset\n"
		"    -v         increase verbosity to debug level\n"
		"    -V VOLUME  volume to get metadata from\n"
	);
}



int main(int argc, char **argv)
{
	if(argc < 2)
	{
		usage();
		exit(EXIT_FAILURE);
	}
	
	int optchar = 0;
	char *volume_path = NULL;
	
	bitlocker_dataset_t* dataset = NULL;
	datum_vmk_t* vmk_clear_key_datum = NULL;
	
	off_t offset     = 0;
	DIS_LOGS verbosity = L_INFO;
	
	while((optchar = getopt(argc, argv, "o:V:hv")) != -1)
	{
		switch(optchar)
		{
			case 'h':
				usage();
				return EXIT_SUCCESS;
			case 'o':
				offset = (off_t) strtoll(optarg, NULL, 10);
				break;
			case 'v':
				verbosity = L_DEBUG;
				break;
			case 'V':
				volume_path = strdup(optarg);
				break;
			case '?':
			default:
				fprintf(stderr, "Unknown option encountered.\n");
				usage();
				exit(EXIT_FAILURE);
		}
	}
	
	if(!volume_path)
	{
		usage();
		exit(EXIT_FAILURE);
	}
	
	dis_context_t dis_ctx = dis_new();
	
	/*
	 * Initialize dislocker's configuration
	 */
	dis_setopt(&dis_ctx->cfg, DIS_OPT_VOLUME_PATH,   volume_path);
	dis_setopt(&dis_ctx->cfg, DIS_OPT_VOLUME_OFFSET, &offset);
	dis_setopt(&dis_ctx->cfg, DIS_OPT_VERBOSITY,     &verbosity);
	
	/* We don't want to give decryption mean, we only want the metadata */
	dis_state_e init_state = DIS_STATE_AFTER_BITLOCKER_INFORMATION_CHECK;
	dis_setopt(&dis_ctx->cfg, DIS_OPT_INITIALIZE_STATE, &init_state);
	
	/* Initialize dislocker */
	if(dis_initialize(dis_ctx) != DIS_RET_SUCCESS)
	{
		xprintf(L_CRITICAL, "Can't initialize dislocker. Abort.\n");
		return EXIT_FAILURE;
	}
	
	
	// Printing volume header
	print_volume_header(L_INFO, dis_ctx->io_data.volume_header);
	xprintf(L_INFO, "\n");
	
	// Printing BitLocker information metadata
	print_information(L_INFO, dis_ctx->io_data.information);
	xprintf(L_INFO, "\n");
	
	// Now we're looking at the data themselves
	print_data(L_INFO, dis_ctx->io_data.information);
	
	
	// Get the information's dataset
	if(!get_dataset(dis_ctx->io_data.information, &dataset))
	{
		xprintf(L_CRITICAL, "Can't find a valid dataset. Abort.\n");
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	// Search for a clear key
	if(has_clear_key(dataset, &vmk_clear_key_datum))
	{
		xprintf(L_INFO, "=======[ There's a clear key here ]========\n");
		print_one_datum(L_INFO, (void*)vmk_clear_key_datum);
		xprintf(L_INFO, "=============[ Clear key end ]=============\n");
	}
	else
		xprintf(L_INFO, "No clear key found.\n");
	
	
	dis_destroy(dis_ctx);
	
	return EXIT_SUCCESS;
}
