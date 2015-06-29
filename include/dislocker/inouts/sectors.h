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
#ifndef SECTORS_H
#define SECTORS_H

#include <stdint.h>
#include "dislocker/xstd/xstdio.h"
#include "dislocker/inouts/inouts.h"



/*
 * Functions prototypes
 */
int read_decrypt_sectors(
	dis_iodata_t* io_data,
	size_t nb_read_sector,
	uint16_t sector_size,
	off_t sector_start,
	uint8_t* output
);
int encrypt_write_sectors(
	dis_iodata_t* io_data,
	size_t nb_write_sector,
	uint16_t sector_size,
	off_t sector_start,
	uint8_t* input
);

#endif /* SECTORS_H */
