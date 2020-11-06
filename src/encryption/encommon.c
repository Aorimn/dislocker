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
#include "dislocker/return_values.h"
#include "dislocker/xstd/xstdio.h"
#include "dislocker/xstd/xstdlib.h"
#include "dislocker/encryption/encrypt.h"
#include "dislocker/encryption/decrypt.h"
#include "dislocker/encryption/encommon.priv.h"

#include <string.h>


/**
 * Create "an object" of type dis_crypt_t
 *
 * @param sector_size The sector size is needed for various operations. It's the
 * size to be used for decrypting the disc as it's encrypted sector by sector.
 * @param disk_cipher Indicate the encryption used on the disk for data.
 * @return The newly allocated dis_crypt_t "object".
 */
dis_crypt_t dis_crypt_new(uint16_t sector_size, cipher_t disk_cipher)
{
	dis_crypt_t crypt = dis_malloc(sizeof(struct _dis_crypt));
	memset(crypt, 0, sizeof(struct _dis_crypt));
	crypt->sector_size = sector_size;

	if(disk_cipher == AES_128_DIFFUSER || disk_cipher == AES_256_DIFFUSER)
	{
		crypt->flags |= DIS_ENC_FLAG_USE_DIFFUSER;
		crypt->encrypt_fn = encrypt_cbc_with_diffuser;
		crypt->decrypt_fn = decrypt_cbc_with_diffuser;
	}
	else if(disk_cipher == AES_XTS_128 || disk_cipher == AES_XTS_256)
	{
		crypt->encrypt_fn = encrypt_xts;
		crypt->decrypt_fn = decrypt_xts;
	}
	else
	{
		crypt->encrypt_fn = encrypt_cbc_without_diffuser;
		crypt->decrypt_fn = decrypt_cbc_without_diffuser;
	}

	return crypt;
}

int dis_crypt_set_fvekey(dis_crypt_t crypt, uint16_t algorithm, uint8_t* fvekey)
{
	if(!crypt || !fvekey)
		return DIS_RET_ERROR_DISLOCKER_INVAL;

	switch(algorithm)
	{
		case AES_128_DIFFUSER:
			AES_SETENC_KEY(&crypt->ctx.TWEAK_E_ctx, fvekey + 0x20, 128);
			AES_SETDEC_KEY(&crypt->ctx.TWEAK_D_ctx, fvekey + 0x20, 128);
			// fall through
		case AES_128_NO_DIFFUSER:
			AES_SETENC_KEY(&crypt->ctx.FVEK_E_ctx, fvekey, 128);
			AES_SETDEC_KEY(&crypt->ctx.FVEK_D_ctx, fvekey, 128);
			return DIS_RET_SUCCESS;

		case AES_256_DIFFUSER:
			AES_SETENC_KEY(&crypt->ctx.TWEAK_E_ctx, fvekey + 0x20, 256);
			AES_SETDEC_KEY(&crypt->ctx.TWEAK_D_ctx, fvekey + 0x20, 256);
			// fall through
		case AES_256_NO_DIFFUSER:
			AES_SETENC_KEY(&crypt->ctx.FVEK_E_ctx, fvekey, 256);
			AES_SETDEC_KEY(&crypt->ctx.FVEK_D_ctx, fvekey, 256);
			return DIS_RET_SUCCESS;

		case AES_XTS_128:
			AES_SETENC_KEY(&crypt->ctx.FVEK_E_ctx, fvekey, 128);
			AES_SETDEC_KEY(&crypt->ctx.FVEK_D_ctx, fvekey, 128);
			AES_SETENC_KEY(&crypt->ctx.TWEAK_E_ctx, fvekey + 0x10, 128);
			AES_SETDEC_KEY(&crypt->ctx.TWEAK_D_ctx, fvekey + 0x10, 128);
			return DIS_RET_SUCCESS;

		case AES_XTS_256:
			AES_SETENC_KEY(&crypt->ctx.FVEK_E_ctx, fvekey, 256);
			AES_SETDEC_KEY(&crypt->ctx.FVEK_D_ctx, fvekey, 256);
			AES_SETENC_KEY(&crypt->ctx.TWEAK_E_ctx, fvekey + 0x20, 256);
			AES_SETDEC_KEY(&crypt->ctx.TWEAK_D_ctx, fvekey + 0x20, 256);
			return DIS_RET_SUCCESS;

		default:
			dis_printf(L_WARNING, "Algo not supported: %#hx\n", algorithm);
			break;
	}

	return DIS_RET_ERROR_CRYPTO_ALGORITHM_UNSUPPORTED;
}

void dis_crypt_destroy(dis_crypt_t crypt)
{
	if(crypt)
		dis_free(crypt);
}
