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


#include "common.h"
#include "metadata/datums.h"
#include "encryption/diffuser.h"
#include "encrypt.h"




/*
 * Below are some prototypes of functions used by decrypt_sector 
 */
void encrypt_without_diffuser(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer);
void encrypt_with_diffuser   (contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer);



/**
 * Interface to encrypt a sector
 * 
 * @param global_data Data needed by FUSE and the encryption to deal with encrypted data
 * @param sector The sector to encrypt
 * @param buffer The place where we have to put encrypted data
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int encrypt_sector(dis_iodata_t* global_data, uint8_t* sector, off_t sector_address, uint8_t* buffer)
{
	// Check parameters
	if(!global_data || !sector || !buffer)
		return FALSE;
	
	
	switch(global_data->metadata->dataset.algorithm)
	{
		case AES_128_DIFFUSER:
		case AES_256_DIFFUSER:
			encrypt_with_diffuser(global_data->enc_ctx, global_data->sector_size, sector, sector_address, buffer);
			break;
		case AES_128_NO_DIFFUSER:
		case AES_256_NO_DIFFUSER:
			encrypt_without_diffuser(global_data->enc_ctx, global_data->sector_size, sector, sector_address, buffer);
			break;
	}
	
	return TRUE;
}


/**
 * Encrypt a sector whithout the diffuser
 * 
 * @param ctx AES's contexts
 * @param sector_size Size of a sector (in bytes)
 * @param sector The sector to encrypt
 * @param sector_address Address of the sector to encrypt
 * @param buffer The place where we have to put encrypted data
 */
void encrypt_without_diffuser(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer)
{
	/* Parameters are assumed to be correctly checked already */
	
	unsigned char iv[16] = {0,};
	
	/* Create the iv */
	*(off_t*)iv = sector_address;
	AES_ECB_ENC(&ctx->FVEK_E_ctx, AES_ENCRYPT, iv, iv);
	
	/* Actually encrypt data */
	AES_CBC(&ctx->FVEK_E_ctx, AES_ENCRYPT, sector_size, iv, sector, buffer);
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
void encrypt_with_diffuser(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer)
{
	/* Parameters are assumed to be correctly checked already */
	
	uint8_t iv[16] = {0,};
	uint8_t sector_key[32] = {0,};
	
	int loop = 0;
	
	
	/* First, create the sector key */
	*(off_t*)iv = sector_address;
	
	AES_ECB_ENC(&ctx->TWEAK_E_ctx, AES_ENCRYPT, iv, sector_key);
	/* For iv unicity reason... */
	iv[15] = 0x80;
	AES_ECB_ENC(&ctx->TWEAK_E_ctx, AES_ENCRYPT, iv, &sector_key[16]);
	
	memcpy(buffer, sector, sector_size);
	
	/* Then apply the sector key */
	for(loop = 0; loop < sector_size; ++loop)
		buffer[loop] ^= sector_key[loop % 32];
	
	
	/* Afterward, call diffuser A */
	diffuserA_encrypt(buffer, sector_size, (uint32_t*)buffer);
	
	
	/* Call diffuser B */
	diffuserB_encrypt(buffer, sector_size, (uint32_t*)buffer);
	
	
	/* And finally, actually encrypt the buffer */
	encrypt_without_diffuser(ctx, sector_size, buffer, sector_address, buffer);
	
	memset(sector_key, 0, 32);
}



