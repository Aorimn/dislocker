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
#ifndef DECRYPT_H
#define DECRYPT_H


#define AUTHENTICATOR_LENGTH 16


#include <sys/types.h>
#include "dislocker/xstd/xstdio.h" // Only for off_t
#include "dislocker/encryption/encommon.h"




/*
 * Prototypes
 */
int decrypt_key(
	unsigned char* input,
	unsigned int   input_size,
	unsigned char* mac,
	unsigned char* nonce,
	unsigned char* key,
	unsigned int   keybits,
	void** output
);

void decrypt_cbc_without_diffuser(
	dis_aes_contexts_t* ctx,
	uint16_t sector_size,
	uint8_t* sector,
	off_t sector_address,
	uint8_t* buffer
);

void decrypt_cbc_with_diffuser(
	dis_aes_contexts_t* ctx,
	uint16_t sector_size,
	uint8_t* sector,
	off_t sector_address,
	uint8_t* buffer
);

void decrypt_xts(
	dis_aes_contexts_t* ctx,
	uint16_t sector_size,
	uint8_t* sector,
	off_t sector_address,
	uint8_t* buffer
);

int decrypt_sector(dis_crypt_t crypt, uint8_t* sector, off_t sector_address, uint8_t* buffer);



#endif /* DECRYPT_H */
