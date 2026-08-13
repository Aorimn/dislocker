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
 * Extract and display BitLocker recovery password from a volume
 */

#define _GNU_SOURCE 1

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

#include "dislocker/common.h"
#include "dislocker/return_values.h"
#include "dislocker/config.h"
#include "dislocker/dislocker.h"


void usage()
{
	fprintf(stderr,
		"Usage: " PROGNAME " -V VOLUME DECRYPTMETHOD [-hqv]\n"
		"    with DECRYPTMETHOD = -p[RECOVERY_PASSWORD]|-f BEK_FILE|-u[USER_PASSWORD]|-c\n"
		"\n"
		"    -c, --clearkey        decrypt volume using a clear key\n"
		"    -f, --bekfile BEKFILE\n"
		"                          decrypt volume using the bek file (on USB key)\n"
		"    -h, --help            print this help and exit\n"
		"    -p, --recovery-password=[RECOVERY_PASSWORD]\n"
		"                          decrypt volume using the recovery password method\n"
		"    -q, --quiet           do NOT display anything except the password\n"
		"    -u, --user-password=[USER_PASSWORD]\n"
		"                          decrypt volume using the user password method\n"
		"    -v, --verbosity       increase verbosity to debug level\n"
		"    -V, --volume VOLUME   volume to get recovery password from\n"
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
	int ret = EXIT_SUCCESS;
	dis_context_t dis_ctx = NULL;
	char recovery_password[56]; /* 8*6 + 7 + 1 */

	/* Initialize dislocker context */
	dis_ctx = dis_new();
	if(dis_ctx == NULL)
	{
		fprintf(stderr, "Failed to allocate dislocker context\n");
		return EXIT_FAILURE;
	}

	/* Parse options */
	while((optchar = getopt(argc, argv, "cf:hp::qu::vV:")) != -1)
	{
		int trueval = TRUE;
		switch(optchar)
		{
			case 'c':
				dis_setopt(dis_ctx, DIS_OPT_USE_CLEAR_KEY, &trueval);
				break;
			case 'f':
				dis_setopt(dis_ctx, DIS_OPT_USE_BEK_FILE, &trueval);
				dis_setopt(dis_ctx, DIS_OPT_SET_BEK_FILE_PATH, optarg);
				break;
			case 'h':
				usage();
				dis_destroy(dis_ctx);
				return EXIT_SUCCESS;
			case 'p':
				dis_setopt(dis_ctx, DIS_OPT_USE_RECOVERY_PASSWORD, &trueval);
				dis_setopt(dis_ctx, DIS_OPT_SET_RECOVERY_PASSWORD, optarg);
				break;
			case 'q':
			{
				DIS_LOGS l = L_QUIET;
				dis_setopt(dis_ctx, DIS_OPT_VERBOSITY, &l);
				break;
			}
			case 'u':
				dis_setopt(dis_ctx, DIS_OPT_USE_USER_PASSWORD, &trueval);
				dis_setopt(dis_ctx, DIS_OPT_SET_USER_PASSWORD, optarg);
				break;
			case 'v':
			{
				DIS_LOGS l = L_DEBUG;
				dis_setopt(dis_ctx, DIS_OPT_VERBOSITY, &l);
				break;
			}
			case 'V':
				dis_setopt(dis_ctx, DIS_OPT_VOLUME_PATH, optarg);
				break;
			case '?':
			default:
				fprintf(stderr, "Unknown option encountered.\n");
				usage();
				dis_destroy(dis_ctx);
				return EXIT_FAILURE;
		}
	}

	/* We only need to initialize up to the VMK state */
	dis_state_e stop_state = DIS_STATE_AFTER_VMK;
	dis_setopt(dis_ctx, DIS_OPT_INITIALIZE_STATE, &stop_state);

	/* Don't check volume state - we're only extracting the recovery password */
	int trueval = TRUE;
	dis_setopt(dis_ctx, DIS_OPT_DONT_CHECK_VOLUME_STATE, &trueval);

	/* Initialize dislocker (will stop after VMK decryption) */
	ret = dis_initialize(dis_ctx);
	if(ret != DIS_STATE_AFTER_VMK && ret != DIS_RET_SUCCESS)
	{
		fprintf(stderr, "Failed to initialize dislocker (error %d)\n", ret);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}

	/* Extract the recovery password */
	ret = dis_get_recovery_password(dis_ctx, recovery_password);
	if(ret != DIS_RET_SUCCESS)
	{
		fprintf(stderr, "Failed to extract recovery password (error %d)\n", ret);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}

	/* Print the recovery password to stdout */
	printf("%s\n", recovery_password);

	/* Clean up */
	dis_destroy(dis_ctx);

	return EXIT_SUCCESS;
}
