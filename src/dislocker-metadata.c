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

#define _GNU_SOURCE 1

#include <getopt.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dislocker/return_values.h"
#include "dislocker/config.h"
#include "dislocker/dislocker.h"
#include "dislocker/metadata/datums.h"
#include "dislocker/metadata/metadata.h"
#include "dislocker/metadata/print_metadata.h"

/*
 * On Darwin and FreeBSD, files are opened using 64 bits offsets/variables
 * and O_LARGEFILE isn't defined
 */
#if defined(__DARWIN) || defined(__FREEBSD)
#  define O_LARGEFILE 0
#endif /* __DARWIN || __FREEBSD */



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
	dis_metadata_config_t dis_meta_cfg = NULL;
	dis_metadata_t dis_metadata = NULL;
	int fve_fd = -1;

	void* vmk_clear_key_datum = NULL;

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
				volume_path = optarg;
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

	/* Initialize outputs */
	dis_stdio_init(verbosity, NULL);

	dis_printf(L_INFO, PROGNAME " by " AUTHOR ", v" VERSION " (compiled for " __OS "/" __ARCH ")\n");
#ifdef VERSION_DBG
	dis_printf(L_INFO, "Compiled version: " VERSION_DBG "\n");
#endif

	/* Open the volume as a (big) normal file */
	dis_printf(L_DEBUG, "Trying to open '%s'...\n", volume_path);
	fve_fd = dis_open(volume_path, O_RDONLY|O_LARGEFILE);

	/*
	 * Initialize dislocker's configuration
	 *
	 */
	dis_meta_cfg = dis_metadata_config_new();
	dis_meta_cfg->fve_fd       = fve_fd;
	dis_meta_cfg->offset       = offset;
	dis_meta_cfg->readonly     = 1;

	dis_metadata = dis_metadata_new(dis_meta_cfg);
	if(dis_metadata_initialize(dis_metadata) != DIS_RET_SUCCESS)
	{
		dis_printf(L_CRITICAL, "Can't initialize dislocker. Abort.\n");
		return EXIT_FAILURE;
	}


	// Printing volume header
	print_volume_header(L_INFO, dis_metadata);
	dis_printf(L_INFO, "\n");

	// Printing BitLocker information metadata
	print_information(L_INFO, dis_metadata);
	dis_printf(L_INFO, "\n");

	// Now we're looking at the data themselves
	print_data(L_INFO, dis_metadata);


	// Search for a clear key
	if(dis_metadata_has_clear_key(dis_metadata, &vmk_clear_key_datum))
	{
		dis_printf(L_INFO, "=======[ There's a clear key here ]========\n");
		print_one_datum(L_INFO, vmk_clear_key_datum);
		dis_printf(L_INFO, "=============[ Clear key end ]=============\n");
	}
	else
		dis_printf(L_INFO, "No clear key found.\n");


	dis_close(fve_fd);
	dis_metadata_destroy(dis_metadata);

	return EXIT_SUCCESS;
}
