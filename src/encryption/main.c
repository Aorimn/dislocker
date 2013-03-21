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
/*
 * Test of the encryption/decryption algorithms
 */



#include <unistd.h>


#include "common.h"
#include "metadata/metadata.h"

#include "encrypt.h"
#include "decrypt.h"



/*
 * Prototypes of functions we'll use
 */
void encrypt_without_diffuser(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer);
void encrypt_with_diffuser(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer);

void decrypt_without_diffuser(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer);
void decrypt_with_diffuser(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer);





void usage()
{
	fprintf(stderr, "Usage: "PROGNAME" {-h|-m STRING [-d] [-s {128|256}]}\n"
					"\n"
					"    -d             use the diffuser algorithm   \n"
					"    -h             display this help and exit   \n"
					"    -m STRING      a string to crypt and decrypt\n"
					"    -s {128|256}   choose key length            \n"
					"\n"
		   );
}


int init_keys(uint8_t* cipher_key, contexts_t* ctx, long int algo_length, int use_diffuser)
{
	// Check parameters
	if(!cipher_key || !ctx || (algo_length != 128 && algo_length != 256))
		return FALSE;
	
	if(algo_length == 128)
	{
		AES_SETENC_KEY(&ctx->FVEK_E_ctx, cipher_key, 128);
		AES_SETDEC_KEY(&ctx->FVEK_D_ctx, cipher_key, 128);
		
		if(use_diffuser)
		{
			AES_SETENC_KEY(&ctx->TWEAK_E_ctx, cipher_key + 0x20, 128);
			AES_SETDEC_KEY(&ctx->TWEAK_D_ctx, cipher_key + 0x20, 128);
		}
	}
	
	if(algo_length == 256)
	{
		AES_SETENC_KEY(&ctx->FVEK_E_ctx, cipher_key, 256);
		AES_SETDEC_KEY(&ctx->FVEK_D_ctx, cipher_key, 256);
		
		if(use_diffuser)
		{
			AES_SETENC_KEY(&ctx->TWEAK_E_ctx, cipher_key + 0x20, 256);
			AES_SETDEC_KEY(&ctx->TWEAK_D_ctx, cipher_key + 0x20, 256);
		}
	}
	
	
	return TRUE;
}





int main(int argc, char** argv)
{
	// Check parameters number
	if(argc < 2)
	{
		usage();
		exit(EXIT_FAILURE);
	}
	
	
	int optchar = 0;
	
	
	unsigned char* clear_string   = NULL;
	size_t string_len    = 0;
	
	long int algo_length = 128;
	
	int use_diffuser     = 0;
	
	
	while((optchar = getopt(argc, argv, "m:s:hd")) != -1)
	{
		switch(optchar)
		{
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
				break;
			case 'd':
				use_diffuser = 1;
				break;
			case 'm':
				clear_string = (unsigned char*) strdup(optarg);
				break;
			case 's':
				if((algo_length = strtol(optarg, NULL, 10)) != 128
						&& algo_length != 256)
					algo_length = 128;
				break;
			case '?':
			default:
				fprintf(stderr, "Unknown option encountered.\n");
				usage();
				exit(EXIT_FAILURE);
		}
	}
	
	xstdio_init(L_INFO, NULL);
	
	
	/* Check parameters */
	if(!clear_string || (string_len = strlen((char*)clear_string)) <= 0)
	{
		xprintf(L_CRITICAL, "Error: no clear string given, abort.\n");
		exit(EXIT_FAILURE);
	}
	
	/* Get the real string length */
	string_len++;
	
	
	/* Initiate ciphers functions */
	void(*encrypt_function)(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer);
	void(*decrypt_function)(contexts_t* ctx, uint16_t sector_size, uint8_t* sector, off_t sector_address, uint8_t* buffer);
	
	if(use_diffuser)
	{
		xprintf(L_INFO, "-- Using the diffuser -- key length %ld bits...\n", algo_length);
		encrypt_function = encrypt_with_diffuser;
		decrypt_function = decrypt_with_diffuser;
	}
	else
	{
		xprintf(L_INFO, "-- Not using the diffuser -- key length %ld bits...\n", algo_length);
		encrypt_function = encrypt_without_diffuser;
		decrypt_function = decrypt_without_diffuser;
	}
	
	
	/* Now prepare the ciphers keys */
	unsigned char cipher_key[] = "\xfb\xc4\xca\x62\x03\x00\x51\xcc\xcd\xde\x0b\x95\x5f\x3d"
	                             "\xa6\x55\x50\xab\x78\xa2\xd1\x7e\x26\x18\x2d\xd3\xa1\x1d"
	                             "\xf1\x1f\xec\xb9\x3a\x0b\x13\x39\x30\x82\x55\x13\xaa\xa9"
	                             "\x57\x27\xca\x7f\x2e\x3d\x17\x04\x08\x3c\x2b\x6f\xaf\x4d"
	                             "\x53\x09\x21\xb0\xad\x66\x38\xc6";
	contexts_t ctx;
	memset(&ctx, 0, sizeof(contexts_t));
	
	
	if(!init_keys(cipher_key, &ctx, algo_length, use_diffuser))
	{
		xprintf(L_CRITICAL, "Error: failed to initialize keys, abort.\n");
		exit(EXIT_FAILURE);
	}
	
	xprintf(L_INFO, "-------------{ Initial length : %6d }------------------\n", string_len);
	
	/* Need padding to make the clear message length divisible by 16 for AES-CBC algorithm */
	size_t padding = 0;
	while(((string_len + padding) % 16) != 0)
		padding++;
	
	string_len += padding;
	xprintf(L_INFO, "-------------{ New length : %10d }------------------\n", string_len);
	
	if(padding)
	{
		clear_string = realloc(clear_string, string_len);
		if(!clear_string)
			exit(42);
	}
	
	unsigned char* encrypted_string = xmalloc(string_len * sizeof(unsigned char));
	unsigned char* decrypted_string = xmalloc(string_len * sizeof(unsigned char));
	memset(encrypted_string, 0, string_len);
	memset(decrypted_string, 0, string_len);
	
	/* Initialise padded data */
	while(padding)
	{
		clear_string[string_len - padding] = 0;
		padding--;
	}
	
	
	
	/*
	 * Now do the complete encryption/decryption process
	 */
	xprintf(L_INFO, "==========================================================\n");
	xprintf(L_INFO, "Clear message is '%s' or in an hexa format:\n", clear_string);
	hexdump(L_INFO, clear_string, string_len);
	
	uint16_t len = (uint16_t)string_len;
	if((size_t)len != string_len)
	{
		while((size_t)len != string_len)
		{
			encrypt_function(&ctx, len, clear_string, 0, encrypted_string);
			len = (uint16_t)((uint16_t)string_len - len);
		}
	}
	
	if(len != 0)
		encrypt_function(&ctx, len, clear_string, 0, encrypted_string);
	
	
	xprintf(L_INFO, "==========================================================\n");
	
	len = (uint16_t)string_len;
	if((size_t)len != string_len)
	{
		while((size_t)len != string_len)
		{
			decrypt_function(&ctx, len, encrypted_string, 0, decrypted_string);
			len = (uint16_t)((uint16_t)string_len - len);
		}
	}
	
	if(len != 0)
		decrypt_function(&ctx, len, encrypted_string, 0, decrypted_string);
	
	xprintf(L_INFO, "==========================================================\n");
	xprintf(L_INFO, "Clear message is again '%s' or in an hexa format:\n", decrypted_string);
	hexdump(L_INFO, decrypted_string, string_len);
	
	xprintf(L_INFO, "==========================================================\n");
	
	
	if(memcmp(clear_string, decrypted_string, string_len) == 0)
		xprintf(L_INFO, "It seems ok!\n");
	else
		xprintf(L_INFO, "Damn it!\n");
	
	xfree(clear_string);
	xfree(encrypted_string);
	xfree(decrypted_string);
	
	xstdio_end();
	
	
	return EXIT_SUCCESS;
}



