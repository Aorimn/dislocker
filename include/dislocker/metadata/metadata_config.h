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
#ifndef METADATA_CONFIG_H
#define METADATA_CONFIG_H

#include "dislocker/config.h"


/**
 * Metadata structure to use to query the functions below
 */
typedef struct _dis_metadata_config* dis_metadata_config_t;


struct _dis_metadata_config {
	/* The file descriptor to the encrypted volume */
	int           fve_fd;

	/*
	 * Use this block of metadata and not another one (begin at 1, 0 is for not
	 * forcing anything)
	 */
	unsigned char force_block;

	/*
	 * Begin to read the BitLocker volume at this offset, making this offset the
	 * zero-one
	 */
	off_t         offset;

	/* States dislocker's metadata initialisation is at or will be stopped at */
	dis_state_e   curr_state;
	dis_state_e   init_stop_at;

	/* Readonly mode for EOW support */
	int readonly;
};




/*
 * Prototypes
 */
dis_metadata_config_t dis_metadata_config_new();
void dis_metadata_config_destroy(dis_metadata_config_t dis_metadata_cfg);



#endif // METADATA_CONFIG_H
