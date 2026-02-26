/* -*- coding: utf-8 -*- */
/* -*- mode: c -*- */
/*
 * Dislocker -- enables to read/write on BitLocker encrypted partitions under
 * Linux
 * Copyright (C) 2026 Arm Ltd.
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
#ifndef SSL_BINDINGS_H
#define SSL_BINDINGS_H

#include <string.h>

#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define DIS_OSSL_MAX_AES_KEY_BYTES 512/8

typedef struct dis_ossl_aes_ctx dis_ossl_aes_ctx;
struct dis_ossl_aes_ctx {
	unsigned char key[DIS_OSSL_MAX_AES_KEY_BYTES];
	size_t len;
	int enc_dec;
	EVP_CIPHER_CTX *ossl_ctx;
};

#define AES_CONTEXT                     dis_ossl_aes_ctx

#define DIS_OSSL_CIPHER_ECB 0
#define DIS_OSSL_CIPHER_CBC 1

static inline const EVP_CIPHER *dis_ossl_get_cipher(size_t key_len, int ossl_mode)
{
	if (ossl_mode == DIS_OSSL_CIPHER_ECB)
	{
		switch (key_len)
		{
			case 16: return EVP_aes_128_ecb();
			case 24: return EVP_aes_192_ecb();
			case 32: return EVP_aes_256_ecb();
			default: return NULL;
		}
	}
	else if (ossl_mode == DIS_OSSL_CIPHER_CBC)
	{
		switch (key_len)
		{
			case 16: return EVP_aes_128_cbc();
			case 24: return EVP_aes_192_cbc();
			case 32: return EVP_aes_256_cbc();
			default: return NULL;
		}
	}
	return NULL;
}

static inline int dis_ossl_set_key(AES_CONTEXT *ctx, const unsigned char *key, size_t key_bits, int enc_dec)
{
	size_t key_len = key_bits / 8;
	if (key_len > sizeof(ctx->key))
		return 1;
	if (!ctx->ossl_ctx)
	{
		ctx->ossl_ctx = EVP_CIPHER_CTX_new();
		if (!ctx->ossl_ctx)
			return 1;
	}

	memcpy(ctx->key, key, key_len);
	ctx->len = key_len;
	ctx->enc_dec = enc_dec;

	return 0;
}

static inline void dis_ossl_free(AES_CONTEXT *ctx)
{
	if (!ctx)
		return;

	EVP_CIPHER_CTX_free(ctx->ossl_ctx);
	ctx->ossl_ctx = NULL;
	OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
}

static inline int dis_ossl_aes_crypt(
	AES_CONTEXT *ctx,
	int mode,
	int size,
	const unsigned char *iv,
	const unsigned char *input,
	unsigned char *output,
	int cipher)
{
	int out_len = 0;

	const EVP_CIPHER *ossl_cipher = dis_ossl_get_cipher(ctx->len, cipher);
	if (!ossl_cipher)
		return 1;

	/* Initialization code in AES_SETENC_KEY() or AES_SETDEC_KEY() has called EVP_CIPHER_CTX_new() */
	EVP_CIPHER_CTX *ossl_ctx = ctx->ossl_ctx;
	if (!ossl_ctx)
		return 1;

	if (!EVP_CIPHER_CTX_reset(ossl_ctx))
		return 1;

	if (!EVP_CipherInit_ex(ossl_ctx, ossl_cipher, NULL, ctx->key, iv, mode == AES_ENCRYPT)) return 1;
	if (!EVP_CIPHER_CTX_set_padding(ossl_ctx, 0)) return 1;
	if (!EVP_CipherUpdate(ossl_ctx, output, &out_len, input, size)) return 1;
	if (!EVP_CipherFinal_ex(ossl_ctx, &output[out_len], &out_len)) return 1;

	return 0;
}

#define AES_SETENC_KEY(ctx, key, size)  dis_ossl_set_key(ctx, key, size, AES_ENCRYPT)
#define AES_SETDEC_KEY(ctx, key, size)  dis_ossl_set_key(ctx, key, size, AES_DECRYPT)
#define AES_FREE(ctx)	dis_ossl_free(ctx)
#define AES_ECB_ENC(ctx, mode, in, out) dis_ossl_aes_crypt(ctx, mode, 16, NULL, in, out, DIS_OSSL_CIPHER_ECB)
#define AES_CBC(ctx, mode, size, iv, in, out) dis_ossl_aes_crypt(ctx, mode, size, iv, in, out, DIS_OSSL_CIPHER_CBC)

/*
 * OpenSSL doesn't provide XEX, so just use the dislocker implementations. Note that
 * the dislocker implementations use the OpenSSL primitives already defined, these are optional
 */
#include "dislocker/encryption/aes-xts.h"
#define AES_XEX(ctx1, ctx2, mode, size, iv, in, out) \
			  dis_aes_crypt_xex(ctx1, ctx2, mode, size, iv, in, out)

#define AES_XTS(ctx1, ctx2, mode, size, iv, in, out) \
			  dis_aes_crypt_xts(ctx1, ctx2, mode, size, iv, in, out)

#endif /* SSL_BINDINGS_H */
