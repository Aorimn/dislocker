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


#include <string.h>

#include "dislocker/encryption/diffuser.h"


#define ROTATE_LEFT(a,n)  (((a) << (n)) | ((a) >> ((sizeof(a) * 8)-(n))))
#define ROTATE_RIGHT(a,n) (((a) >> (n)) | ((a) << ((sizeof(a) * 8)-(n))))


/**
 * Implement diffuser A's decryption algorithm as explained by Niels Ferguson
 * @warning sector and buffer should not overlap
 *
 * @param sector The sector to de-diffuse
 * @param sector_size The size of the sector (in bytes)
 * @param buffer The resulted de-diffused data
 */
void diffuserA_decrypt(uint8_t* sector, uint16_t sector_size, uint32_t* buffer)
{
	int i = 0;
	int Acycles = 5;
	uint16_t Ra[] = {9, 0, 13, 0};
	/* buffer is a pointer on a 4 bytes object */
	uint16_t int_size = sector_size / 4;

	/* Use buffer for the algorithm */
	if((uint8_t*)buffer != sector)
		memcpy(buffer, sector, sector_size);

	while(Acycles)
	{
		for(i = 0; i < int_size; ++i)
		{
			*(buffer + i) = *(buffer + i) +                                               // d[i] +
					( /* Remember that, for instance, -5 % 2 yields -1, not 1 as expected */
						*(buffer + ((i-2 + int_size) % int_size)) ^                       // d[i-2] xor
						ROTATE_LEFT(*(buffer + ((i-5 + int_size) % int_size)), Ra[i % 4]) // ROTATE_LEFT(d[i-5], Ra[i mod 4])
					);
		}

		Acycles--;
	}
}



/**
 * Implement diffuser B's decryption algorithm as explained by Niels Ferguson
 * @warning sector and buffer should not overlap
 *
 * @param sector The sector to de-diffuse
 * @param sector_size The size of the sector (in bytes)
 * @param buffer The resulted de-diffused data
 */
void diffuserB_decrypt(uint8_t* sector, uint16_t sector_size, uint32_t* buffer)
{
	int i = 0;
	int Bcycles = 3;
	uint16_t Rb[] = {0, 10, 0, 25};
	/* buffer is a pointer on a 4 bytes object */
	uint16_t int_size = sector_size / 4;

	/* Use buffer for the algorithm */
	if((uint8_t*)buffer != sector)
		memcpy(buffer, sector, sector_size);


	while(Bcycles)
	{
		for(i = 0; i < int_size; ++i)
		{
			*(buffer+i) = *(buffer + i) +                                      // d[i] +
					(
						*(buffer + ((i+2) % int_size)) ^                       // d[i+2] xor
						ROTATE_LEFT(*(buffer + ((i+5) % int_size)), Rb[i % 4]) // ROTATE_LEFT(d[i+5], Rb[i mod 4])
					);
		}

		Bcycles--;
	}
}




/**
 * Implement diffuser A's encryption algorithm as explained by Niels Ferguson
 * @warning sector and buffer should not overlap
 *
 * @param sector The sector to diffuse
 * @param sector_size The size of the sector (in bytes)
 * @param buffer The resulted diffused data
 */
void diffuserA_encrypt(uint8_t* sector, uint16_t sector_size, uint32_t* buffer)
{
	int i = 0;
	int Acycles = 5;
	uint16_t Ra[] = {9, 0, 13, 0};
	/* buffer is a pointer on a 4 bytes object */
	uint16_t int_size = sector_size / 4;

	/* Use buffer for the algorithm */
	if((uint8_t*)buffer != sector)
		memcpy(buffer, sector, sector_size);

	while(Acycles)
	{
		for(i = int_size - 1; i >= 0; --i)
		{
			*(buffer + i) = *(buffer + i) -                                               // d[i] -
					( /* Remember that, for instance, -5 % 2 yields -1, not 1 as expected */
						*(buffer + ((i-2 + int_size) % int_size)) ^                       // d[i-2] xor
						ROTATE_LEFT(*(buffer + ((i-5 + int_size) % int_size)), Ra[i % 4]) // ROTATE_LEFT(d[i-5], Ra[i mod 4])
					);
		}

		Acycles--;
	}
}


/**
 * Implement diffuser B's encryption algorithm as explained by Niels Ferguson
 * @warning sector and buffer should not overlap
 *
 * @param sector The sector to diffuse
 * @param sector_size The size of the sector (in bytes)
 * @param buffer The resulted diffused data
 */
void diffuserB_encrypt(uint8_t* sector, uint16_t sector_size, uint32_t* buffer)
{
	int i = 0;
	int Bcycles = 3;
	uint16_t Rb[] = {0, 10, 0, 25};
	/* buffer is a pointer on a 4 bytes object */
	uint16_t int_size = sector_size >> 2;

	/* Use buffer for the algorithm */
	if((uint8_t*)buffer != sector)
		memcpy(buffer, sector, sector_size);

	while(Bcycles)
	{
		for(i = int_size - 1; i >= 0; --i)
		{
			*(buffer+i) = *(buffer + i) -                                      // d[i] -
					(
						*(buffer + ((i+2) % int_size)) ^                       // d[i+2] xor
						ROTATE_LEFT(*(buffer + ((i+5) % int_size)), Rb[i % 4]) // ROTATE_LEFT(d[i+5], Rb[i mod 4])
					);
		}

		Bcycles--;
	}
}
