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


#include "dislocker/accesses/stretch_key.h"


#define SHA256_DIGEST_LENGTH 32
#define SALT_LENGTH          16


// Needed structure to 'stretch' a password
typedef struct {
	uint8_t updated_hash[SHA256_DIGEST_LENGTH];
	uint8_t password_hash[SHA256_DIGEST_LENGTH];
	uint8_t salt[SALT_LENGTH];
	uint64_t hash_count;
} bitlocker_chain_hash_t;



/* This prototype is for internal use only */
static int stretch_key(bitlocker_chain_hash_t* ch, uint8_t *result);


/**
 * Function implementing the algorithm of the chain hash, described by Jesse D.
 * Kornblum.
 * Ref: http://jessekornblum.com/presentations/di09.pdf
 * @see stretch_key()
 *
 * @param recovery_key The 16-bytes recovery key previously distilled (16 bytes)
 * @param salt The salt used for crypto (16 bytes)
 * @param result Will contain the resulting hash key (32 bytes)
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int stretch_recovery_key(const uint8_t *recovery_key,
                         const uint8_t *salt,
                         uint8_t *result)
{
	if(!recovery_key || !salt || !result)
	{
		dis_printf(L_ERROR, "Invalid parameter given to stretch_recovery_key().\n");
		return FALSE;
	}

	size_t size = sizeof(bitlocker_chain_hash_t);
	bitlocker_chain_hash_t * ch = NULL;

	ch = (bitlocker_chain_hash_t *) dis_malloc(size);

	memset(ch, 0, size);

	/* 16 is the size of the recovery_key, in bytes (see doc above) */
	SHA256(recovery_key, 16, ch->password_hash);

	memcpy(ch->salt, salt, SALT_LENGTH);

	dis_printf(L_INFO, "Stretching the recovery password, it could take some time...\n");
	if(!stretch_key(ch, result))
		return FALSE;
	dis_printf(L_INFO, "Stretching of the recovery password is now ok!\n");

	/* Wipe out with zeros and free it */
	memclean(ch, size);

	return TRUE;
}


/**
 * Function implementing the stretching of a hashed user password.
 * @see stretch_key()
 *
 * @param user_hash The 32-bytes hash from SHA256(SHA256(UTF16(user_password)))
 * @param salt The salt used for crypto (16 bytes)
 * @param result Will contain the resulting hash key (32 bytes)
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int stretch_user_key(const uint8_t *user_hash,
                     const uint8_t *salt,
                     uint8_t *result)
{
	if(!user_hash || !salt || !result)
	{
		dis_printf(L_ERROR, "Invalid parameter given to stretch_user_key().\n");
		return FALSE;
	}

	size_t size = sizeof(bitlocker_chain_hash_t);
	bitlocker_chain_hash_t ch;

	memset(&ch, 0, size);

	memcpy(ch.password_hash, user_hash, SHA256_DIGEST_LENGTH);
	memcpy(ch.salt,          salt,      SALT_LENGTH);

	dis_printf(L_INFO, "Stretching the user password, it could take some time...\n");
	if(!stretch_key(&ch, result))
		return FALSE;
	dis_printf(L_INFO, "Stretching of the user password is now ok!\n");

	/* Wipe out with zeros */
	memset(&ch, 0, size);

	return TRUE;
}


/**
 * Core function implementing the chain hash algorithm.
 * @see stretch_recovery_key()
 *
 * @param ch A pointer to a bitlocker_chain_hash_t structure
 * @param result Will contain the resulting hash key (32 bytes)
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int stretch_key(bitlocker_chain_hash_t* ch, uint8_t *result)
{
	if(!ch || !result)
	{
		dis_printf(L_ERROR, "Invalid parameter given to stretch_key().\n");
		return FALSE;
	}

	size_t   size = sizeof(bitlocker_chain_hash_t);
	uint64_t loop = 0;

	for(loop = 0; loop < 0x100000; ++loop)
	{
		SHA256((unsigned char *)ch, size, ch->updated_hash);

		ch->hash_count++;
	}

	memcpy(result, ch->updated_hash, SHA256_DIGEST_LENGTH);

	return TRUE;
}
