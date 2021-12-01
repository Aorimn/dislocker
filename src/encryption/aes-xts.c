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

#include <stdint.h>
#include <string.h>

#include "dislocker/ssl_bindings.h"

#ifndef GET_UINT64_LE
#define GET_UINT64_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint64_t) (b)[(i) + 7] << 56 )             \
        | ( (uint64_t) (b)[(i) + 6] << 48 )             \
        | ( (uint64_t) (b)[(i) + 5] << 40 )             \
        | ( (uint64_t) (b)[(i) + 4] << 32 )             \
        | ( (uint64_t) (b)[(i) + 3] << 24 )             \
        | ( (uint64_t) (b)[(i) + 2] << 16 )             \
        | ( (uint64_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint64_t) (b)[(i)    ]       );            \
}
#endif

#ifndef PUT_UINT64_LE
#define PUT_UINT64_LE(n,b,i)                            \
{                                                       \
    (b)[(i) + 7] = (unsigned char) ( (n) >> 56 );       \
    (b)[(i) + 6] = (unsigned char) ( (n) >> 48 );       \
    (b)[(i) + 5] = (unsigned char) ( (n) >> 40 );       \
    (b)[(i) + 4] = (unsigned char) ( (n) >> 32 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
}
#endif

#define gf128mul_dat(q) { \
	q(0x00), q(0x01), q(0x02), q(0x03), q(0x04), q(0x05), q(0x06), q(0x07),\
	q(0x08), q(0x09), q(0x0a), q(0x0b), q(0x0c), q(0x0d), q(0x0e), q(0x0f),\
	q(0x10), q(0x11), q(0x12), q(0x13), q(0x14), q(0x15), q(0x16), q(0x17),\
	q(0x18), q(0x19), q(0x1a), q(0x1b), q(0x1c), q(0x1d), q(0x1e), q(0x1f),\
	q(0x20), q(0x21), q(0x22), q(0x23), q(0x24), q(0x25), q(0x26), q(0x27),\
	q(0x28), q(0x29), q(0x2a), q(0x2b), q(0x2c), q(0x2d), q(0x2e), q(0x2f),\
	q(0x30), q(0x31), q(0x32), q(0x33), q(0x34), q(0x35), q(0x36), q(0x37),\
	q(0x38), q(0x39), q(0x3a), q(0x3b), q(0x3c), q(0x3d), q(0x3e), q(0x3f),\
	q(0x40), q(0x41), q(0x42), q(0x43), q(0x44), q(0x45), q(0x46), q(0x47),\
	q(0x48), q(0x49), q(0x4a), q(0x4b), q(0x4c), q(0x4d), q(0x4e), q(0x4f),\
	q(0x50), q(0x51), q(0x52), q(0x53), q(0x54), q(0x55), q(0x56), q(0x57),\
	q(0x58), q(0x59), q(0x5a), q(0x5b), q(0x5c), q(0x5d), q(0x5e), q(0x5f),\
	q(0x60), q(0x61), q(0x62), q(0x63), q(0x64), q(0x65), q(0x66), q(0x67),\
	q(0x68), q(0x69), q(0x6a), q(0x6b), q(0x6c), q(0x6d), q(0x6e), q(0x6f),\
	q(0x70), q(0x71), q(0x72), q(0x73), q(0x74), q(0x75), q(0x76), q(0x77),\
	q(0x78), q(0x79), q(0x7a), q(0x7b), q(0x7c), q(0x7d), q(0x7e), q(0x7f),\
	q(0x80), q(0x81), q(0x82), q(0x83), q(0x84), q(0x85), q(0x86), q(0x87),\
	q(0x88), q(0x89), q(0x8a), q(0x8b), q(0x8c), q(0x8d), q(0x8e), q(0x8f),\
	q(0x90), q(0x91), q(0x92), q(0x93), q(0x94), q(0x95), q(0x96), q(0x97),\
	q(0x98), q(0x99), q(0x9a), q(0x9b), q(0x9c), q(0x9d), q(0x9e), q(0x9f),\
	q(0xa0), q(0xa1), q(0xa2), q(0xa3), q(0xa4), q(0xa5), q(0xa6), q(0xa7),\
	q(0xa8), q(0xa9), q(0xaa), q(0xab), q(0xac), q(0xad), q(0xae), q(0xaf),\
	q(0xb0), q(0xb1), q(0xb2), q(0xb3), q(0xb4), q(0xb5), q(0xb6), q(0xb7),\
	q(0xb8), q(0xb9), q(0xba), q(0xbb), q(0xbc), q(0xbd), q(0xbe), q(0xbf),\
	q(0xc0), q(0xc1), q(0xc2), q(0xc3), q(0xc4), q(0xc5), q(0xc6), q(0xc7),\
	q(0xc8), q(0xc9), q(0xca), q(0xcb), q(0xcc), q(0xcd), q(0xce), q(0xcf),\
	q(0xd0), q(0xd1), q(0xd2), q(0xd3), q(0xd4), q(0xd5), q(0xd6), q(0xd7),\
	q(0xd8), q(0xd9), q(0xda), q(0xdb), q(0xdc), q(0xdd), q(0xde), q(0xdf),\
	q(0xe0), q(0xe1), q(0xe2), q(0xe3), q(0xe4), q(0xe5), q(0xe6), q(0xe7),\
	q(0xe8), q(0xe9), q(0xea), q(0xeb), q(0xec), q(0xed), q(0xee), q(0xef),\
	q(0xf0), q(0xf1), q(0xf2), q(0xf3), q(0xf4), q(0xf5), q(0xf6), q(0xf7),\
	q(0xf8), q(0xf9), q(0xfa), q(0xfb), q(0xfc), q(0xfd), q(0xfe), q(0xff) \
}

#define xx(p, q)	0x##p##q

#define xda_bbe(i) ( \
	(i & 0x80 ? xx(43, 80) : 0) ^ (i & 0x40 ? xx(21, c0) : 0) ^ \
	(i & 0x20 ? xx(10, e0) : 0) ^ (i & 0x10 ? xx(08, 70) : 0) ^ \
	(i & 0x08 ? xx(04, 38) : 0) ^ (i & 0x04 ? xx(02, 1c) : 0) ^ \
	(i & 0x02 ? xx(01, 0e) : 0) ^ (i & 0x01 ? xx(00, 87) : 0) \
)

static const uint16_t gf128mul_table_bbe[256] = gf128mul_dat(xda_bbe);


typedef unsigned char be128[16];
static void gf128mul_x_ble(be128 r, const be128 x)
{
	uint64_t a, b, ra, rb;
	uint64_t _tt;

	GET_UINT64_LE(a, x, 0);
	GET_UINT64_LE(b, x, 8);

	_tt = gf128mul_table_bbe[b >> 63];
	ra = (a << 1) ^ _tt;
	rb = (b << 1) | (a >> 63);

	PUT_UINT64_LE(ra, r, 0);
	PUT_UINT64_LE(rb, r, 8);
}


/*
 * AES-XEX buffer encryption/decryption
 */
int dis_aes_crypt_xex(
	AES_CONTEXT *crypt_ctx,
	AES_CONTEXT *tweak_ctx,
	int mode,
	size_t length,
	unsigned char *iv,
	const unsigned char *input,
	unsigned char *output
)
{
	union xex_buf128 {
		uint8_t  u8[16];
		uint64_t u64[2];
	};

	union xex_buf128 scratch;
	union xex_buf128 t_buf;
	union xex_buf128 *inbuf;
	union xex_buf128 *outbuf;

	inbuf = (union xex_buf128*)input;
	outbuf = (union xex_buf128*)output;

	if( length % 16 )
		return( -1 );


	AES_ECB_ENC( tweak_ctx, AES_ENCRYPT, iv, t_buf.u8 );

	goto first;

	do
	{
		gf128mul_x_ble( t_buf.u8, t_buf.u8 );

first:
		/* PP <- T xor P */
		scratch.u64[0] = (uint64_t)( inbuf->u64[0] ^ t_buf.u64[0] );
		scratch.u64[1] = (uint64_t)( inbuf->u64[1] ^ t_buf.u64[1] );

		/* CC <- E(Key2,PP) */
		AES_ECB_ENC( crypt_ctx, mode, scratch.u8, outbuf->u8 );

		/* C <- T xor CC */
		outbuf->u64[0] = (uint64_t)( outbuf->u64[0] ^ t_buf.u64[0] );
		outbuf->u64[1] = (uint64_t)( outbuf->u64[1] ^ t_buf.u64[1] );

		inbuf  += 1;
		outbuf += 1;
		length -= 16;
	} while( length > 0 );

	return( 0 );
}


/*
 * AES-XTS buffer encryption/decryption
 */
int dis_aes_crypt_xts(
	AES_CONTEXT *crypt_ctx,
	AES_CONTEXT *tweak_ctx,
	int mode,
	size_t length,
	unsigned char *iv,
	const unsigned char *input,
	unsigned char *output
)
{
	union xts_buf128 {
		uint8_t  u8[16];
		uint64_t u64[2];
	};

	union xts_buf128 scratch;
	union xts_buf128 cts_scratch;
	union xts_buf128 t_buf;
	union xts_buf128 cts_t_buf;
	union xts_buf128 *inbuf;
	union xts_buf128 *outbuf;
	size_t nb_blocks = length / 16;
	size_t remaining = length % 16;

	inbuf = (union xts_buf128*)input;
	outbuf = (union xts_buf128*)output;

	/* For performing the ciphertext-stealing operation, we have to get at least
	 * one complete block */
	if( length < 16 )
		return( -1 );


	AES_ECB_ENC( tweak_ctx, AES_ENCRYPT, iv, t_buf.u8 );

	goto first;

	do
	{
		gf128mul_x_ble( t_buf.u8, t_buf.u8 );

first:
		/* PP <- T xor P */
		scratch.u64[0] = (uint64_t)( inbuf->u64[0] ^ t_buf.u64[0] );
		scratch.u64[1] = (uint64_t)( inbuf->u64[1] ^ t_buf.u64[1] );

		/* CC <- E(Key2,PP) */
		AES_ECB_ENC( crypt_ctx, mode, scratch.u8, outbuf->u8 );

		/* C <- T xor CC */
		outbuf->u64[0] = (uint64_t)( outbuf->u64[0] ^ t_buf.u64[0] );
		outbuf->u64[1] = (uint64_t)( outbuf->u64[1] ^ t_buf.u64[1] );

		inbuf     += 1;
		outbuf    += 1;
		nb_blocks -= 1;
	} while( nb_blocks > 0 );

	/* Ciphertext stealing, if necessary */
	if( remaining != 0 )
	{
		outbuf = (union xts_buf128*)output;
		nb_blocks = length / 16;

		if( mode == AES_ENCRYPT )
		{
			memcpy( cts_scratch.u8, (uint8_t*)&outbuf[nb_blocks], remaining );
			memcpy( cts_scratch.u8 + remaining, ((uint8_t*)&outbuf[nb_blocks - 1]) + remaining, 16 - remaining );
			memcpy( (uint8_t*)&outbuf[nb_blocks], (uint8_t*)&outbuf[nb_blocks - 1], remaining );

			gf128mul_x_ble( t_buf.u8, t_buf.u8 );

			/* PP <- T xor P */
			scratch.u64[0] = (uint64_t)( cts_scratch.u64[0] ^ t_buf.u64[0] );
			scratch.u64[1] = (uint64_t)( cts_scratch.u64[1] ^ t_buf.u64[1] );

			/* CC <- E(Key2,PP) */
			AES_ECB_ENC( crypt_ctx, mode, scratch.u8, scratch.u8 );

			/* C <- T xor CC */
			( &outbuf[nb_blocks - 1] )->u64[0] = (uint64_t)( scratch.u64[0] ^ t_buf.u64[0] );
			( &outbuf[nb_blocks - 1] )->u64[1] = (uint64_t)( scratch.u64[1] ^ t_buf.u64[1] );
		}
		else /* AES_DECRYPT */
		{
			cts_t_buf.u64[0] = t_buf.u64[0];
			cts_t_buf.u64[1] = t_buf.u64[1];

			gf128mul_x_ble( t_buf.u8, t_buf.u8 );

			/* PP <- T xor P */
			scratch.u64[0] = (uint64_t)( outbuf[nb_blocks - 1].u64[0] ^ t_buf.u64[0] );
			scratch.u64[1] = (uint64_t)( outbuf[nb_blocks - 1].u64[1] ^ t_buf.u64[1] );

			/* CC <- E(Key2,PP) */
			AES_ECB_ENC( crypt_ctx, mode, scratch.u8, scratch.u8 );

			/* C <- T xor CC */
			cts_scratch.u64[0] = (uint64_t)( scratch.u64[0] ^ t_buf.u64[0] );
			cts_scratch.u64[1] = (uint64_t)( scratch.u64[1] ^ t_buf.u64[1] );


			memcpy( (uint8_t*)&outbuf[nb_blocks - 1], (uint8_t*)&outbuf[nb_blocks], remaining );
			memcpy( (uint8_t*)&outbuf[nb_blocks - 1] + remaining, cts_scratch.u8, 16 - remaining );
			memcpy( (uint8_t*)&outbuf[nb_blocks], cts_scratch.u8, remaining );


			/* PP <- T xor P */
			scratch.u64[0] = (uint64_t)( ( &outbuf[nb_blocks - 1] )->u64[0] ^ cts_t_buf.u64[0] );
			scratch.u64[1] = (uint64_t)( ( &outbuf[nb_blocks - 1] )->u64[1] ^ cts_t_buf.u64[1] );

			/* CC <- E(Key2,PP) */
			AES_ECB_ENC( crypt_ctx, mode, scratch.u8, scratch.u8 );

			/* C <- T xor CC */
			( &outbuf[nb_blocks - 1] )->u64[0] = (uint64_t)( scratch.u64[0] ^ cts_t_buf.u64[0] );
			( &outbuf[nb_blocks - 1] )->u64[1] = (uint64_t)( scratch.u64[1] ^ cts_t_buf.u64[1] );
		}
	}

	return( 0 );
}
