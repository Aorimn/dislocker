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
#include "dislocker/encryption/decrypt.h"
#include "dislocker/encryption/encommon.priv.h"



/*
 * Two functions used by decrypt_key
 */
static int aes_ccm_encrypt_decrypt(
					AES_CONTEXT* ctx,
					unsigned char* iv, unsigned char iv_length,
					unsigned char* input, unsigned int input_length,
					unsigned char* mac,   unsigned int mac_size,
					unsigned char* output
						   );

static int aes_ccm_compute_unencrypted_tag(
									AES_CONTEXT* ctx,
									unsigned char* iv, unsigned char iv_length,
									unsigned char* buffer, unsigned int buffer_length,
									unsigned char* mac
								   );




/**
 * In order to decrypt keys as VMK or FVEK, use this function
 *
 * @param input The AES encrypted buffer to decrypt
 * @param key The key to decrypt the input buffer (already extracted from a datum_key_t structure)
 * @param output The decrypted result
 * @param output_size The size of the decrypted result
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int decrypt_key(
	unsigned char* input,
	unsigned int   input_size,
	unsigned char* mac,
	unsigned char* nonce,
	unsigned char* key,
	unsigned int   keybits,
	void** output)
{
	// Check parameters
	if(!input || !mac || !nonce || !key || !output)
		return FALSE;


	AES_CONTEXT ctx;

	uint8_t mac_first [AUTHENTICATOR_LENGTH];
	uint8_t mac_second[AUTHENTICATOR_LENGTH];


	/*
	 * Allocate output buffer
	 */
	*output = dis_malloc(input_size);
	memset(*output, 0, input_size);

	/*
	 * Get the MAC
	 */
	memcpy(mac_first, mac, AUTHENTICATOR_LENGTH);



	/*
	 * Set key which is used to decrypt (already extracted from a datum_key_t structure)
	 */
	AES_SETENC_KEY(&ctx, key, keybits);


	/*
	 * Decrypt the input buffer now
	 * NOTE: The 0xc is the nonce length (hardcoded)
	 */
	dis_printf(L_DEBUG, "}--------[ Data passed to aes_ccm_encrypt_decrypt ]--------{\n");
	dis_printf(L_DEBUG, "-- Nonce:\n");
	hexdump(L_DEBUG, nonce, 0xc);
	dis_printf(L_DEBUG, "-- Input buffer:\n");
	hexdump(L_DEBUG, input, input_size);
	dis_printf(L_DEBUG, "-- MAC:\n");
	hexdump(L_DEBUG, mac_first, AUTHENTICATOR_LENGTH);
	dis_printf(L_DEBUG, "}----------------------------------------------------------{\n");

	aes_ccm_encrypt_decrypt(
		&ctx,
		nonce,
		0xc,
		input,
		input_size,
		mac_first,
		AUTHENTICATOR_LENGTH,
		(unsigned char*) *output
	);



	/*
	 * Compute to check decryption
	 */
	memset(mac_second, 0, AUTHENTICATOR_LENGTH);
	aes_ccm_compute_unencrypted_tag(
		&ctx,
		nonce,
		0xc,
		(unsigned char*) *output,
		input_size,
		mac_second
	);


	memset(&ctx, 0, sizeof(AES_CONTEXT));



	/*
	 * Check if the MACs correspond, if not,
	 * we didn't decrypt correctly the input buffer
	 */
	dis_printf(L_DEBUG, "Looking if MACs match...\n");
	dis_printf(L_DEBUG, "They are just below:\n");
	hexdump(L_DEBUG, mac_first, AUTHENTICATOR_LENGTH);
	hexdump(L_DEBUG, mac_second, AUTHENTICATOR_LENGTH);

	if(memcmp(mac_first, mac_second, AUTHENTICATOR_LENGTH) != 0)
	{
		dis_printf(L_ERROR, "The MACs don't match.\n");
		return FALSE;
	}

	dis_printf(L_DEBUG, "Ok, they match!\n");

	memset(mac_first,  0, AUTHENTICATOR_LENGTH);
	memset(mac_second, 0, AUTHENTICATOR_LENGTH);


	return TRUE;
}



/**
 * Internal function to decrypt keys
 *
 * @param ctx AES context
 * @param iv Initializing Vector
 * @param iv_length Length of the Initializing Vector
 * @param input Crypted input buffer
 * @param input_length Input buffer length
 * @param output Decrypted result
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int aes_ccm_encrypt_decrypt(
					 AES_CONTEXT* ctx,
					 unsigned char* nonce, unsigned char nonce_length,
					 unsigned char* input, unsigned int  input_length,
					 unsigned char* mac,   unsigned int  mac_length,
					 unsigned char* output)
{
	// Check parameters
	if(!ctx || !input || !mac || !output)
		return FALSE;

	dis_printf(L_DEBUG, "Entering aes_ccm_encrypt_decrypt...\n");

	unsigned char iv[16];
	unsigned int loop = 0;
	unsigned char tmp_buf[16] = {0,};
	unsigned char* failsafe = NULL;

	/*
	 * Here is how the counter works in microsoft compatible ccm implementation:
	 *
	 * - User supplies a less than 16 bytes and more than 12 bytes iv
	 *
	 * - Copy it in order to form this format:
	 *   15-iv_length-1 (1 byte)  |  iv (max 14 bytes) | counter counting from zero (from 1 to 3 byte)
	 *
	 * - Apply counter mode of aes
	 *
	 * (thanks to Kumar and Kumar for these explanations)
	 */

	memset(iv, 0, sizeof(iv));
	memcpy(iv + 1, nonce, (nonce_length % sizeof(iv)));

	if(15 - nonce_length - 1 < 0)
		return FALSE;

	*iv = (unsigned char)(15 - nonce_length - 1);


	AES_ECB_ENC(ctx, AES_ENCRYPT, iv, tmp_buf);

	dis_printf(L_DEBUG, "\tTmp buffer:\n");
	hexdump(L_DEBUG, tmp_buf, 16);
	dis_printf(L_DEBUG, "\tInput:\n");
	hexdump(L_DEBUG, mac, mac_length);

	xor_buffer(mac, tmp_buf, NULL, mac_length);

	dis_printf(L_DEBUG, "\tOutput:\n");
	hexdump(L_DEBUG, mac, mac_length);


	/* Increment the internal iv counter */
	iv[15] = 1;


	if(input_length > sizeof(iv))
	{
		loop = input_length >> 4;

		dis_printf(L_DEBUG, "Input length: %d, loop: %d\n", input_length, loop);

		do
		{
			AES_ECB_ENC(ctx, AES_ENCRYPT, iv, tmp_buf);

			xor_buffer(input, tmp_buf, output, sizeof(iv));

			iv[15]++;

			/* A failsafe to not have the same iv twice */
			if(!iv[15])
			{
				failsafe = &iv[15];

				do
				{
					failsafe--;
					(*failsafe)++;
				} while(*failsafe == 0 && failsafe >= &iv[0]);
			}

			input += sizeof(iv);
			output += sizeof(iv);
			input_length = (unsigned int)(input_length - sizeof(iv));

		} while(--loop);
	}

	dis_printf(L_DEBUG, "Input length remain: %d\n", input_length);

	/*
	 * Last block
	 */
	if(input_length)
	{
		AES_ECB_ENC(ctx, AES_ENCRYPT, iv, tmp_buf);

		xor_buffer(input, tmp_buf, output, input_length);
	}

	/* Cleanup */
	memset(iv, 0, sizeof(iv));
	memset(tmp_buf, 0, sizeof(tmp_buf));

	dis_printf(L_DEBUG, "Ending aes_ccm_encrypt_decrypt successfully!\n");

	return TRUE;
}


/**
 * Function to validate decryption
 *
 * @param ctx AES context
 * @param iv Initializing Vector
 * @param iv_length Length of the Initializing Vector
 * @param buffer Data buffer
 * @param buffer_length Data buffer length
 * @param mac MAC result to use to validate decryption
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int aes_ccm_compute_unencrypted_tag(
									AES_CONTEXT* ctx,
									unsigned char* nonce, unsigned char nonce_length,
									unsigned char* buffer, unsigned int buffer_length,
									unsigned char* mac)
{
	// Check parameters
	if(!ctx || !buffer || !mac || nonce_length > 0xe)
		return FALSE;

	dis_printf(L_DEBUG, "Entering aes_ccm_compute_unencrypted_tag...\n");

	unsigned char iv[AUTHENTICATOR_LENGTH];
	unsigned int loop = 0;
	unsigned int tmp_size = buffer_length;

	/*
	 * Construct the IV
	 */
	memset(iv, 0, AUTHENTICATOR_LENGTH);
	iv[0] = ((unsigned char)(0xe - nonce_length)) | ((AUTHENTICATOR_LENGTH - 2) & 0xfe) << 2;
	memcpy(iv + 1, nonce, (nonce_length % AUTHENTICATOR_LENGTH));
	for(loop = 15; loop > nonce_length; --loop)
	{
		*(iv + loop) = tmp_size & 0xff;
		tmp_size = tmp_size >> 8;
	}



	/*
	 * Compute algorithm
	 */
	AES_ECB_ENC(ctx, AES_ENCRYPT, iv, iv);


	if(buffer_length > 16)
	{
		loop = buffer_length >> 4;

		do
		{
			dis_printf(L_DEBUG, "\tBuffer:\n");
			hexdump(L_DEBUG, buffer, 16);
			dis_printf(L_DEBUG, "\tInternal IV:\n");
			hexdump(L_DEBUG, iv, 16);

			xor_buffer(iv, buffer, NULL, AUTHENTICATOR_LENGTH);

			AES_ECB_ENC(ctx, AES_ENCRYPT, iv, iv);

			buffer += AUTHENTICATOR_LENGTH;
			buffer_length -= AUTHENTICATOR_LENGTH;

		} while(--loop);
	}

	/*
	 * Last block
	 */
	if(buffer_length)
	{
		xor_buffer(iv, buffer, NULL, buffer_length);
		AES_ECB_ENC(ctx, AES_ENCRYPT, iv, iv);
	}


	memcpy(mac, iv, AUTHENTICATOR_LENGTH);

	memset(iv, 0, AUTHENTICATOR_LENGTH);

	dis_printf(L_DEBUG, "Ending aes_ccm_compute_unencrypted_tag successfully!\n");

	return TRUE;
}





/**
 * Interface to decrypt a sector
 *
 * @param crypt Data needed by the decryption to deal with encrypted data
 * @param sector The sector to decrypt
 * @param sector_address Address of the sector to decrypt
 * @param buffer The place where we have to put decrypted data
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int decrypt_sector(dis_crypt_t crypt, uint8_t* sector, off_t sector_address, uint8_t* buffer)
{
	// Check parameters
	if(!crypt || !sector || !buffer)
		return FALSE;

	crypt->decrypt_fn(
		&crypt->ctx,
		crypt->sector_size,
		sector,
		sector_address,
		buffer
	);

	return TRUE;
}


/**
 * Decrypt a sector which was not encrypted with the diffuser
 *
 * @param ctx AES's contexts
 * @param sector_size Size of a sector (in bytes)
 * @param sector The sector to decrypt
 * @param sector_address Address of the sector to decrypt
 * @param buffer The place where we have to put decrypted data
 */
void decrypt_cbc_without_diffuser(dis_aes_contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer)
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

	/* Actually decrypt data */
	AES_CBC(&ctx->FVEK_D_ctx, AES_DECRYPT, sector_size, iv.multi, sector, buffer);
}


/**
 * Decrypt a sector which was encrypted with the diffuser enabled
 *
 * @param ctx AES's contexts
 * @param sector_size Size of a sector (in bytes)
 * @param sector The sector to decrypt
 * @param sector_address Address of the sector to decrypt
 * @param buffer The place where we have to put decrypted data
 */
void decrypt_cbc_with_diffuser(dis_aes_contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer)
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


	/* Then actually decrypt the buffer */
	decrypt_cbc_without_diffuser(ctx, sector_size, sector, sector_address, buffer);


	/* Call diffuser B */
	diffuserB_decrypt(buffer, sector_size, (uint32_t*)buffer);


	/* Afterward, call diffuser A */
	diffuserA_decrypt(buffer, sector_size, (uint32_t*)buffer);


	/* And finally, apply the sector key */
	for(loop = 0; loop < sector_size; ++loop)
		buffer[loop] ^= sector_key[loop % 32];

	memset(sector_key, 0, 32);
}


/**
 * Decrypt a sector which was encrypted with AES-XTS
 *
 * @param ctx AES's contexts
 * @param sector_size Size of a sector (in bytes)
 * @param sector The sector to decrypt
 * @param sector_address Address of the sector to decrypt
 * @param buffer The place where we have to put decrypted data
 */
void decrypt_xts(
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
		&ctx->FVEK_D_ctx,
		&ctx->TWEAK_E_ctx,
		AES_DECRYPT,
		sector_size,
		iv.multi,
		sector,
		buffer
	);
}
