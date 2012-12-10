/* -*- coding: utf-8 -*- */
/* -*- mode: c -*- */
/*
 * Dislocker -- enables to read/write on BitLocker encrypted partitions under
 * Linux
 * Copyright (C) 2012  Romain Coltel, Hervé Schauer Consultants
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
#include "recovery_password.h"


void usage(char **argv)
{
	fprintf(stderr, "Usage: %s [-h] [-p RECOVERY_PASSWORD]\n"
					"\n"
					"    -h                    print this help and exit\n"
					"    -p RECOVERY_PASSWORD  the recovery password  to compute\n", argv[0]);
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
	uint8_t *recovery_password = NULL;
	uint8_t *recovery_key = NULL;
	uint8_t salt[16] = {
		'\x3b', '\x36', '\xd9', '\x30', '\x72', '\xa2', '\x2e', '\x03',
		'\xf2', '\xed', '\xfe', '\x6f', '\xcd', '\x14', '\xb4', '\x58'
	};
	
	while((optchar = getopt(argc, argv, "p:h")) != -1)
	{
		switch(optchar)
		{
			case 'h':
				usage(argv);
				return 0;
			case 'p':
				recovery_password = (uint8_t *) strdup(optarg);
				break;
			case '?':
			default:
				fprintf(stderr, "Unknown option encountered.\n");
				usage(argv);
				exit(1);
		}
	}
	
	xstdio_init(L_DEBUG, NULL);
	
	xprintf(L_INFO, "Recovery Password: %s\n", (char *)recovery_password);
	
	recovery_key = xmalloc(32 * sizeof(uint8_t));
	
	if(!intermediate_key(recovery_password, salt, recovery_key))
		return 1;
	
	print_intermediate_key(recovery_key);
	
	xfree(recovery_key);
	if(recovery_password)
		xfree(recovery_password);
	
	xstdio_end();
	
	return 0;
}