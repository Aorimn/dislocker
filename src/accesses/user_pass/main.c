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

#include <getopt.h>

#include "common.h"
#include "user_pass.h"
#include "accesses/stretch_key.h"


void usage(char **argv)
{
	fprintf(stderr, "Usage: %s [-h] [-u USER_PASSWORD]\n"
					"\n"
					"    -h                 print this help and exit\n"
					"    -u USER_PASSWORD   a user password to check on the volume\n", argv[0]);
}


int main(int argc, char **argv)
{
	// Check the parameters
	if(argc < 2)
	{
		usage(argv);
		return 1;
	}

	int optchar = 0;
	uint8_t *user_password = NULL;

	uint8_t   user_hash[32]  = {0,};


	uint8_t salt[16] = {0,}; // TODO


	while((optchar = getopt(argc, argv, "u:h")) != -1)
	{
		switch(optchar)
		{
			case 'h':
				usage(argv);
				return 0;
			case 'u':
				user_password = (uint8_t *) strdup(optarg);
				break;
			case '?':
			default:
				fprintf(stderr, "Unknown option encountered.\n");
				usage(argv);
				exit(1);
		}
	}

	xstdio_init(L_DEBUG, NULL);

	if(user_password == NULL)
	{
		dis_printf(L_CRITICAL, "No user password given, aborting.\n");
		goto error;
	}

	dis_printf(L_INFO, "User Password: %s\n", (char *)user_password);

	if(!user_key(user_password, salt, user_hash))
	{
		dis_printf(L_CRITICAL, "Can't stretch the user password, aborting.\n");
		goto error;
	}


	dis_printf(L_INFO, "User hash:\n");
	hexdump(L_INFO, user_hash, 32);


error:
	if(user_password)
		free(user_password);

	xstdio_end();

	return 0;
}
