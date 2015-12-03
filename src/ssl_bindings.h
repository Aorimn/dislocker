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
#ifndef SSL_BINDINGS_H
#define SSL_BINDINGS_H

/*
 * Here stand the bindings for mbedtls SHA256/SHA2/SHA-2 function for dislocker
 */
#define SHA256(input, len, output)       mbedtls_sha256(input, len, output, 0)

/* Here stand the bindings for AES functions and contexts */
#define AES_ENCRYPT                      MBEDTLS_AES_ENCRYPT
#define AES_DECRYPT                      MBEDTLS_AES_DECRYPT
#define AES_CONTEXT                      mbedtls_aes_context
#define AES_SETENC_KEY(ctx, key, size)   mbedtls_aes_setkey_enc(ctx, key, size)
#define AES_SETDEC_KEY(ctx, key, size)   mbedtls_aes_setkey_dec(ctx, key, size)
#define AES_ECB_ENC(ctx, mode, in, out)  mbedtls_aes_crypt_ecb(ctx, mode, in, out)
#define AES_CBC(ctx, mode, size, iv, in, out) \
                                         mbedtls_aes_crypt_cbc(ctx, mode, size, iv, in, out);



#endif /* SSL_BINDINGS_H */
