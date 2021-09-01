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

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dislocker/common.h"
#include "dislocker/metadata/print_metadata.h"
#include "dislocker/metadata/metadata.h"
#include "dislocker/metadata/metadata_config.h"
#include "dislocker/accesses/bek/bekfile.h"

#define USAGE "Usage: %1$s [-h] [-f file.bek]\n" \
              "  Reads .BEK files and prints information about them\n"


void usage(char* prog)
{
	fprintf(stderr, USAGE, prog);
}


int main (int argc, char **argv)
{
	char *filename = NULL;
	int c  = 0;
	int fd = 0;

	void* bek_dataset = NULL;
	dis_metadata_config_t dis_meta_cfg = NULL;

	opterr = 0;

	while((c = getopt (argc, argv, "hf:")) != -1)
	{
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
	}

	dis_stdio_init(L_INFO, NULL);

	if(filename == NULL)
	{
		dis_printf(L_CRITICAL, "Filename must be provided\n");
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	if(( fd = dis_open(filename, O_RDONLY) ) < 0)
	{
		dis_printf(L_CRITICAL, "Failed to open file %s\n", filename);
		return EXIT_FAILURE;
	}

	if(!get_bek_dataset(fd, &bek_dataset))
	{
		dis_printf(L_CRITICAL, "Unable to get the dataset from the BEK file\n");
		return EXIT_FAILURE;
	}

	dis_close(fd);

	/* display infos */
	dis_printf(L_INFO, "BEK File Information: %s\n", filename);

	/* bek header */
	dis_context_t dis_ctx = dis_new();

	/*
	 * The metadata configuration is freed when calling dis_metadata_destroy()
	 */
	dis_meta_cfg = dis_metadata_config_new();
	dis_meta_cfg->fve_fd       = get_fvevol_fd(dis_ctx);
	dis_meta_cfg->force_block  = 0;
	dis_meta_cfg->offset       = 0;
	dis_meta_cfg->init_stop_at = 0;

	dis_metadata_t dis_metadata = dis_metadata_new(dis_meta_cfg);
	dis_metadata_set_dataset(dis_metadata, bek_dataset);
	print_dataset(L_INFO, dis_metadata);

	/* external datum, which contains the decryption key */
	print_one_datum(L_INFO, bek_dataset + 0x30);

	dis_free(bek_dataset);
	dis_metadata_destroy(dis_metadata);
	dis_destroy(dis_ctx);
	dis_stdio_end();

	return EXIT_SUCCESS;
}
