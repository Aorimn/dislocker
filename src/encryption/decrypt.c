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
#include "encryption/diffuser.h"
#include "encryption/decrypt.h"



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
int decrypt_key(datum_aes_ccm_t* input, unsigned char* key, void** output, unsigned int* output_size)
{
	// Check parameters
	if(!input || !key || !output || !output_size)
		return FALSE;
	
	
	AES_CONTEXT ctx;
	unsigned int header_size = 0;
	unsigned char* aes_input_buffer = NULL;
	unsigned int input_size = 0;
	
	uint8_t mac_first [AUTHENTICATOR_LENGTH];
	uint8_t mac_second[AUTHENTICATOR_LENGTH];
	
	
	
	header_size = datum_types_prop[input->header.datum_type].size_header;
	*output_size = input->header.datum_size - header_size;
	input_size = *output_size;
	
	/*
	 * Allocate output buffer
	 */
	*output = xmalloc(*output_size);
	memset(*output, 0, *output_size);
	
	/*
	 * The aes input buffer is data to decrypt
	 */
	aes_input_buffer = xmalloc(*output_size);
	memcpy(aes_input_buffer, (unsigned char*)input + header_size, *output_size);  
	
	/*
	 * Get the MAC
	 */
	memcpy(mac_first, input->mac, AUTHENTICATOR_LENGTH);
	
	
	
	/*
	 * Set key which is used to decrypt (already extracted from a datum_key_t structure)
	 */
	AES_SETENC_KEY(&ctx, key, AES_CTX_LENGTH);
	
	
	/*
	 * Decrypt the input buffer now
	 * NOTE: The 0xc is the nonce length (hardcoded)
	 */
	xprintf(L_DEBUG, "}--------[ Data passed to aes_ccm_encrypt_decrypt ]--------{\n");
	xprintf(L_DEBUG, "-- Nonce:\n");
	hexdump(L_DEBUG, input->nonce, 0xc);
	xprintf(L_DEBUG, "-- Input buffer:\n");
	hexdump(L_DEBUG, aes_input_buffer, input_size);
	xprintf(L_DEBUG, "-- MAC:\n");
	hexdump(L_DEBUG, mac_first, AUTHENTICATOR_LENGTH);
	xprintf(L_DEBUG, "}----------------------------------------------------------{\n");
	
	aes_ccm_encrypt_decrypt(&ctx, input->nonce, 0xc, aes_input_buffer, input_size, mac_first, AUTHENTICATOR_LENGTH, (unsigned char*) *output);
	
	xfree(aes_input_buffer);
	
	
	
	/*
	 * Compute to check decryption
	 */
	memset(mac_second, 0, AUTHENTICATOR_LENGTH);
	aes_ccm_compute_unencrypted_tag(&ctx, input->nonce, 0xc, (unsigned char*) *output, *output_size, mac_second);
	
	
	memset(&ctx, 0, sizeof(AES_CONTEXT));
	
	
	
	/*
	 * Check if the MACs correspond, if not,
	 * we didn't decrypt correctly the input buffer
	 */
	xprintf(L_INFO, "Looking if MACs match...\n");
	xprintf(L_DEBUG, "They are just below:\n");
	hexdump(L_DEBUG, mac_first, AUTHENTICATOR_LENGTH);
	hexdump(L_DEBUG, mac_second, AUTHENTICATOR_LENGTH);
	
	if(memcmp(mac_first, mac_second, AUTHENTICATOR_LENGTH) != 0)
	{
		xprintf(L_ERROR, "The MACs don't match.\n");
		return FALSE;
	}
	
	xprintf(L_INFO, "Ok, they match!\n");
	
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
	
	xprintf(L_INFO, "Entering aes_ccm_encrypt_decrypt...\n");
	
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
	
	xprintf(L_DEBUG, "\tTmp buffer:\n");
	hexdump(L_DEBUG, tmp_buf, 16);
	xprintf(L_DEBUG, "\tInput:\n");
	hexdump(L_DEBUG, mac, mac_length);
	
	xor_buffer(mac, tmp_buf, NULL, mac_length);
	
	xprintf(L_DEBUG, "\tOutput:\n");
	hexdump(L_DEBUG, mac, mac_length);
	
	
	/* Increment the internal iv counter */
	iv[15] = 1; 
	
	
	if(input_length > sizeof(iv))
	{
		loop = input_length >> 4;
		
		xprintf(L_DEBUG, "Input length: %d, loop: %d\n", input_length, loop);
		
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
	
	xprintf(L_DEBUG, "Input length remain: %d\n", input_length);
	
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
	
	xprintf(L_INFO, "Ending aes_ccm_encrypt_decrypt successfully!\n");
	
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
	
	xprintf(L_INFO, "Entering aes_ccm_compute_unencrypted_tag...\n");
	
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
			xprintf(L_DEBUG, "\tBuffer:\n");
			hexdump(L_DEBUG, buffer, 16);
			xprintf(L_DEBUG, "\tInternal IV:\n");
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
	
	xprintf(L_INFO, "Ending aes_ccm_compute_unencrypted_tag successfully!\n");
	
	return TRUE;
}






/*
 * Below are some prototypes of functions used by decrypt_sector
 */
void decrypt_without_diffuser(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer);
void decrypt_with_diffuser   (contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer);



/**
 * Interface to decrypt a sector
 * 
 * @param global_data Data needed by FUSE and the decryption to deal with encrypted data
 * @param sector The sector to decrypt
 * @param buffer The place where we have to put decrypted data
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int decrypt_sector(dis_iodata_t* global_data, uint8_t* sector, off_t sector_address, uint8_t* buffer)
{
	// Check parameters
	if(!global_data || !sector || !buffer)
		return FALSE;
	
	
	switch(global_data->metadata->dataset.algorithm)
	{
		case AES_128_DIFFUSER:
		case AES_256_DIFFUSER:
			decrypt_with_diffuser(global_data->enc_ctx, global_data->sector_size, sector, sector_address, buffer);
			break;
		case AES_128_NO_DIFFUSER:
		case AES_256_NO_DIFFUSER:
			decrypt_without_diffuser(global_data->enc_ctx, global_data->sector_size, sector, sector_address, buffer);
			break;
	}
	
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
void decrypt_without_diffuser(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer)
{
	/* Parameters are assumed to be correctly checked already */
	
	unsigned char iv[16] = {0,};
	
	/* Create the iv */
	*(off_t*)iv = sector_address;
	AES_ECB_ENC(&ctx->FVEK_E_ctx, AES_ENCRYPT, iv, iv);
	
	/* Actually decrypt data */
	AES_CBC(&ctx->FVEK_D_ctx, AES_DECRYPT, sector_size, iv, sector, buffer);
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
void decrypt_with_diffuser(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer)
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
	
	
	/* Then actually decrypt the buffer */
	decrypt_without_diffuser(ctx, sector_size, sector, sector_address, buffer);
	
	
	/* Call diffuser B */
	diffuserB_decrypt(buffer, sector_size, (uint32_t*)buffer);
	
	
	/* Afterward, call diffuser A */
	diffuserA_decrypt(buffer, sector_size, (uint32_t*)buffer);
	
	
	/* And finally, apply the sector key */
	for(loop = 0; loop < sector_size; ++loop)
		buffer[loop] ^= sector_key[loop % 32];
	
	memset(sector_key, 0, 32);
}



