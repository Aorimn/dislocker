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


#include "dislocker/common.h"
#include "dislocker/encryption/diffuser.h"
#include "dislocker/encryption/encrypt.h"
#include "dislocker/encryption/encommon.priv.h"



/**
 * Interface to encrypt a sector
 *
 * @param crypt Data needed by the encryption to deal with encrypted data
 * @param sector The sector to encrypt
 * @param sector_address The address of the sector to encrypt
 * @param buffer The place where we have to put encrypted data
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int encrypt_sector(dis_crypt_t crypt, uint8_t* sector, off_t sector_address, uint8_t* buffer)
{
	// Check parameters
	if(!crypt || !sector || !buffer)
		return FALSE;

	crypt->encrypt_fn(
		&crypt->ctx,
		crypt->sector_size,
		sector,
		sector_address,
		buffer
	);

	return TRUE;
}


/**
 * Encrypt a sector without the diffuser
 *
 * @param ctx AES's contexts
 * @param sector_size Size of a sector (in bytes)
 * @param sector The sector to encrypt
 * @param sector_address Address of the sector to encrypt
 * @param buffer The place where we have to put encrypted data
 */
void encrypt_cbc_without_diffuser(dis_aes_contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer)
{
	/* Parameters are assumed to be correctly checked already */

	union {
		unsigned char multi[16];
		off_t single;
	} iv;
	memset(iv.multi, 0, 16);

	/* Create the iv */
	iv.single = sector_address;
	AES_ECB_ENC(&ctx->FVEK_E_ctx, AES_ENCRYPT, iv.multi, iv.multi);

	/* Actually encrypt data */
	AES_CBC(&ctx->FVEK_E_ctx, AES_ENCRYPT, sector_size, iv.multi, sector, buffer);
}


/**
 * Encrypt a sector when the diffuser is enabled
 *
 * @param ctx AES's contexts
 * @param sector_size Size of a sector (in bytes)
 * @param sector The sector to encrypt
 * @param sector_address Address of the sector to encrypt
 * @param buffer The place where we have to put encrypted data
 */
void encrypt_cbc_with_diffuser(dis_aes_contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer)
{
	/* Parameters are assumed to be correctly checked already */

	union {
		uint8_t multi[16];
		off_t single;
	} iv;
	memset(iv.multi, 0, 16);
	uint8_t sector_key[32] = {0,};

	int loop = 0;


	/* First, create the sector key */
	iv.single = sector_address;

	AES_ECB_ENC(&ctx->TWEAK_E_ctx, AES_ENCRYPT, iv.multi, sector_key);
	/* For iv unicity reason... */
	iv.multi[15] = 0x80;
	AES_ECB_ENC(&ctx->TWEAK_E_ctx, AES_ENCRYPT, iv.multi, &sector_key[16]);

	memcpy(buffer, sector, sector_size);

	/* Then apply the sector key */
	for(loop = 0; loop < sector_size; ++loop)
		buffer[loop] ^= sector_key[loop % 32];


	/* Afterward, call diffuser A */
	diffuserA_encrypt(buffer, sector_size, (uint32_t*)buffer);


	/* Call diffuser B */
	diffuserB_encrypt(buffer, sector_size, (uint32_t*)buffer);


	/* And finally, actually encrypt the buffer */
	encrypt_cbc_without_diffuser(ctx, sector_size, buffer, sector_address, buffer);

	memset(sector_key, 0, 32);
}


/**
 * Encrypt a sector when the diffuser is enabled
 *
 * @param ctx AES's contexts
 * @param sector_size Size of a sector (in bytes)
 * @param sector The sector to encrypt
 * @param sector_address Address of the sector to encrypt
 * @param buffer The place where we have to put encrypted data
 */
void encrypt_xts(
	dis_aes_contexts_t* ctx,
	uint16_t sector_size,
	uint8_t* sector,
	off_t sector_address,
	uint8_t* buffer)
{
	/* Parameters are assumed to be correctly checked already */
	union {
		unsigned char multi[16];
		off_t single;
	} iv;

	/* Create the iv */
	memset(iv.multi, 0, 16);
	iv.single = sector_address / sector_size;

	AES_XTS(
		&ctx->FVEK_E_ctx,
		&ctx->TWEAK_E_ctx,
		AES_ENCRYPT,
		sector_size,
		iv.multi,
		sector,
		buffer
	);
}
