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

#include "ssl_bindings.h"

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

typedef unsigned char be128[16];
static void gf128mul_x_ble(be128 r, const be128 x)
{
	uint64_t a, b, ra, rb;
	uint64_t mask;

	GET_UINT64_LE(a, x, 0);
	GET_UINT64_LE(b, x, 8);

	/* Constant-time branchless reduction by x^128 + x^7 + x^2 + x + 1 (0x87) */
	mask = (uint64_t)-(int64_t)(b >> 63);
	ra = (a << 1) ^ (0x87ULL & mask);
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
	union xex_buf128 in_block;
	union xex_buf128 out_block;
	const unsigned char *inbuf = input;
	unsigned char *outbuf = output;

	if( length % 16 )
		return( -1 );


	AES_ECB_ENC( tweak_ctx, AES_ENCRYPT, iv, t_buf.u8 );

	goto first;

	do
	{
		gf128mul_x_ble( t_buf.u8, t_buf.u8 );

first:
		memcpy( in_block.u8, inbuf, 16 );

		/* PP <- T xor P */
		scratch.u64[0] = (uint64_t)( in_block.u64[0] ^ t_buf.u64[0] );
		scratch.u64[1] = (uint64_t)( in_block.u64[1] ^ t_buf.u64[1] );

		/* CC <- E(Key2,PP) */
		AES_ECB_ENC( crypt_ctx, mode, scratch.u8, out_block.u8 );

		/* C <- T xor CC */
		out_block.u64[0] = (uint64_t)( out_block.u64[0] ^ t_buf.u64[0] );
		out_block.u64[1] = (uint64_t)( out_block.u64[1] ^ t_buf.u64[1] );

		memcpy( outbuf, out_block.u8, 16 );

		inbuf  += 16;
		outbuf += 16;
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
	union xts_buf128 in_block;
	union xts_buf128 out_block;
	const unsigned char *inbuf = input;
	unsigned char *outbuf = output;
	size_t nb_blocks = length / 16;
	size_t remaining = length % 16;

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
		memcpy( in_block.u8, inbuf, 16 );

		/* PP <- T xor P */
		scratch.u64[0] = (uint64_t)( in_block.u64[0] ^ t_buf.u64[0] );
		scratch.u64[1] = (uint64_t)( in_block.u64[1] ^ t_buf.u64[1] );

		/* CC <- E(Key2,PP) */
		AES_ECB_ENC( crypt_ctx, mode, scratch.u8, out_block.u8 );

		/* C <- T xor CC */
		out_block.u64[0] = (uint64_t)( out_block.u64[0] ^ t_buf.u64[0] );
		out_block.u64[1] = (uint64_t)( out_block.u64[1] ^ t_buf.u64[1] );

		memcpy( outbuf, out_block.u8, 16 );

		inbuf     += 16;
		outbuf    += 16;
		nb_blocks -= 1;
	} while( nb_blocks > 0 );

	/* Ciphertext stealing, if necessary */
	if( remaining != 0 )
	{
		nb_blocks = length / 16;
		unsigned char *last_full = output + (nb_blocks - 1) * 16;
		unsigned char *tail = output + nb_blocks * 16;
		const unsigned char *in_tail = input + nb_blocks * 16;

		if( mode == AES_ENCRYPT )
		{
			memcpy( cts_scratch.u8, in_tail, remaining );
			memcpy( cts_scratch.u8 + remaining, last_full + remaining, 16 - remaining );
			memcpy( tail, last_full, remaining );

			gf128mul_x_ble( t_buf.u8, t_buf.u8 );

			/* PP <- T xor P */
			scratch.u64[0] = (uint64_t)( cts_scratch.u64[0] ^ t_buf.u64[0] );
			scratch.u64[1] = (uint64_t)( cts_scratch.u64[1] ^ t_buf.u64[1] );

			/* CC <- E(Key2,PP) */
			AES_ECB_ENC( crypt_ctx, mode, scratch.u8, scratch.u8 );

			/* C <- T xor CC */
			out_block.u64[0] = (uint64_t)( scratch.u64[0] ^ t_buf.u64[0] );
			out_block.u64[1] = (uint64_t)( scratch.u64[1] ^ t_buf.u64[1] );
			memcpy( last_full, out_block.u8, 16 );
		}
		else /* AES_DECRYPT */
		{
			cts_t_buf.u64[0] = t_buf.u64[0];
			cts_t_buf.u64[1] = t_buf.u64[1];

			gf128mul_x_ble( t_buf.u8, t_buf.u8 );

			memcpy( out_block.u8, last_full, 16 );

			/* PP <- T xor P */
			scratch.u64[0] = (uint64_t)( out_block.u64[0] ^ t_buf.u64[0] );
			scratch.u64[1] = (uint64_t)( out_block.u64[1] ^ t_buf.u64[1] );

			/* CC <- E(Key2,PP) */
			AES_ECB_ENC( crypt_ctx, mode, scratch.u8, scratch.u8 );

			/* C <- T xor CC */
			cts_scratch.u64[0] = (uint64_t)( scratch.u64[0] ^ t_buf.u64[0] );
			cts_scratch.u64[1] = (uint64_t)( scratch.u64[1] ^ t_buf.u64[1] );

			memcpy( out_block.u8, in_tail, remaining );
			memcpy( out_block.u8 + remaining, cts_scratch.u8, 16 - remaining );
			memcpy( tail, cts_scratch.u8, remaining );

			/* PP <- T xor P */
			scratch.u64[0] = (uint64_t)( out_block.u64[0] ^ cts_t_buf.u64[0] );
			scratch.u64[1] = (uint64_t)( out_block.u64[1] ^ cts_t_buf.u64[1] );

			/* CC <- E(Key2,PP) */
			AES_ECB_ENC( crypt_ctx, mode, scratch.u8, scratch.u8 );

			/* C <- T xor CC */
			out_block.u64[0] = (uint64_t)( scratch.u64[0] ^ cts_t_buf.u64[0] );
			out_block.u64[1] = (uint64_t)( scratch.u64[1] ^ cts_t_buf.u64[1] );
			memcpy( last_full, out_block.u8, 16 );
		}
	}

	return( 0 );
}
