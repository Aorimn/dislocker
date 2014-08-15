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


/*
 * Number of thread you want to run for enc/decryption
 * NOTE: FUSE uses its own threads so the FUSE's functions can be called in
 * parallel. Use the environment variable FUSE_THREAD_STACK to change the
 * FUSE's threads number.
 */
#define NB_THREAD 2

#include <pthread.h>

#include "dislocker.h"


/* Struct we pass to a thread for buffer enc/decryption */
typedef struct _thread_arg
{
	size_t   nb_loop;
	
	uint16_t sector_size;
	off_t    sector_start;
	
	uint8_t* input;
	uint8_t* output;
	
	unsigned int modulo;
	unsigned int modulo_result;
	
	dis_iodata_t* io_data;
} thread_arg_t;




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
