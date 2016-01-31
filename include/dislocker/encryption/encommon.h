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
#ifndef ENCOMMON_H
#define ENCOMMON_H

#include <stdint.h>

/**
 * Cipher used within BitLocker
 */
enum cipher_types
{
	STRETCH_KEY   = 0x1000,
	AES_CCM_256_0 = 0x2000,
	AES_CCM_256_1 = 0x2001,
	EXTERN_KEY    = 0x2002,
	VMK           = 0x2003,
	AES_CCM_256_2 = 0x2004,
	HASH_256      = 0x2005,

	AES_128_DIFFUSER    = 0x8000,
	AES_256_DIFFUSER    = 0x8001,
	AES_128_NO_DIFFUSER = 0x8002,
	AES_256_NO_DIFFUSER = 0x8003,
	AES_XTS_128         = 0x8004,
	AES_XTS_256         = 0x8005,

	DIS_CIPHER_LOWEST_SUPPORTED  = 0x8000,
	DIS_CIPHER_HIGHEST_SUPPORTED = 0x8005,
};
typedef uint16_t cipher_t;


/**
 * AES contexts "used" during encryption/decryption
 * @see encryption/decrypt.c
 * @see encryption/encrypt.c
 */
typedef struct _aes_contexts dis_aes_contexts_t;

/**
 * Crypt structure used for the encryption operations
 */
typedef struct _dis_crypt* dis_crypt_t;



/*
 * Prototypes
 */
dis_crypt_t dis_crypt_new(uint16_t sector_size, cipher_t disk_cipher);

int dis_crypt_set_fvekey(dis_crypt_t crypt, uint16_t algorithm, uint8_t* fvekey);

void dis_crypt_destroy(dis_crypt_t crypt);


#endif /* ENCOMMON_H */
