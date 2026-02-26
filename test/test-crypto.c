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
#include <setjmp.h>
#include <stdio.h>
#include <string.h>

#include "ssl_bindings.h"

#include "test.h"
#include "test_vectors.h"

static void test_ecb_encrypt_128(void)
{
	AES_CONTEXT ctx = {0};

	NEW_ARRAY_FROM(unsigned char, buf, orig_16);

	/* Test AES ECB 128 Encryption */
	AES_SETENC_KEY(&ctx, key_aes_128, sizeof(key_aes_128) * 8);

	AES_ECB_ENC(&ctx, AES_ENCRYPT, buf, buf);

	CHECK_STATIC_BUFFERS(buf, aes_ecb_128_expected);

	/* Test AES ECB 128 Decryption */
	AES_SETDEC_KEY(&ctx, key_aes_128, sizeof(key_aes_128) * 8);

	AES_ECB_ENC(&ctx, AES_DECRYPT, buf, buf);

	CHECK_STATIC_BUFFERS(buf, orig_16);
	
	AES_FREE(&ctx);
}

static void test_ecb_encrypt_256(void) {
	AES_CONTEXT ctx = {0};

	NEW_ARRAY_FROM(unsigned char, buf, orig_16);

	/* Test AES ECB 256 Encryption */
	AES_SETENC_KEY(&ctx, key_aes_256, sizeof(key_aes_256) * 8);

	AES_ECB_ENC(&ctx, AES_ENCRYPT, buf, buf);

	CHECK_STATIC_BUFFERS(buf, expected_aes_ecb_256);

	/* Test AES ECB 256 Decryption */
	AES_SETDEC_KEY(&ctx, key_aes_256, sizeof(key_aes_256) * 8);

	AES_ECB_ENC(&ctx, AES_DECRYPT, buf, buf);

	CHECK_STATIC_BUFFERS(buf, orig_16);

	AES_FREE(&ctx);
}

static void test_cbc_encrypt_128(void) {
	AES_CONTEXT ctx = {0};

	NEW_ARRAY_FROM(unsigned char, buf, orig_512);

	/* mbedtls requires a mutable IV */
	NEW_ARRAY_FROM(unsigned char, iv, static_iv);

	/* Test AES CBC 128 Encryption
	 *
	 * In at least one test, modify the key to ensure the internal
	 * context buffer doesn't depend on the key pointer remaining
	 * constant.
	 */
	unsigned char mutable_key[sizeof(key_aes_128)];
	memcpy(mutable_key, key_aes_128, sizeof(mutable_key));
	AES_SETENC_KEY(&ctx, mutable_key, sizeof(key_aes_128) * 8);
	memset(mutable_key, 0xFF, sizeof(mutable_key));

	AES_CBC(&ctx, AES_ENCRYPT, sizeof(buf), iv, buf, buf);

	CHECK_STATIC_BUFFERS(buf, expected_cbc_128);

	/* Test AES CBC 128 Decryption */
	memcpy(iv, static_iv, sizeof(iv));

	AES_SETDEC_KEY(&ctx, key_aes_128, sizeof(key_aes_128) * 8);

	AES_CBC(&ctx, AES_DECRYPT, sizeof(expected_cbc_128), iv, expected_cbc_128, buf);

	CHECK_STATIC_BUFFERS(buf, orig_512);

	AES_FREE(&ctx);
}

static void test_cbc_encrypt_256(void) {
	AES_CONTEXT ctx = {0};

	NEW_ARRAY_FROM(unsigned char, buf, orig_512);

	/* mbedtls requires a mutable IV */
	NEW_ARRAY_FROM(unsigned char, iv, static_iv);

	/* Test AES CBC 256 Encryption */
	AES_SETENC_KEY(&ctx, key_aes_256, sizeof(key_aes_256) * 8);

	AES_CBC(&ctx, AES_ENCRYPT, sizeof(buf), iv, buf, buf);

	CHECK_STATIC_BUFFERS(buf, expected_cbc_256);

	/* Test AES CBC 256 Decryption */
	memcpy(iv, static_iv, sizeof(iv));

	AES_SETDEC_KEY(&ctx, key_aes_256, sizeof(key_aes_256) * 8);

	AES_CBC(&ctx, AES_DECRYPT, sizeof(expected_cbc_256), iv, expected_cbc_256, buf);

	CHECK_STATIC_BUFFERS(buf, orig_512);

	AES_FREE(&ctx);
}


int main(int argc, char *argv[])
{
	ADD_TEST(test_ecb_encrypt_128);
	ADD_TEST(test_ecb_encrypt_256);

	ADD_TEST(test_cbc_encrypt_128);
	ADD_TEST(test_cbc_encrypt_256);

	printf("--- Statistics ---\n");
	printf("Total: %d\n", _tests);
	printf("Pass:  %d\n", _tests - _failures);
	printf("Fail:  %d\n", _failures);
	printf("-------------------\n");

	return _failures & 0xFF;
}
