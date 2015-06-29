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
 * Here stand the bindings for polarssl SHA256/SHA2/SHA-2 function for dislocker
 */
#include "polarssl/config.h"
#include "polarssl/version.h"

// Function's name changed
#if defined(POLARSSL_SHA256_C)

#include "polarssl/sha256.h"
#define SHA256(input, len, output)       sha256(input, len, output, 0)

#else /* defined(POLARSSL_SHA256_C) */

#include "polarssl/sha2.h"
// 0x00630500 = version 0.99.5, argument's type changed in this release
#if POLARSSL_VERSION_NUMBER >= 0x00630500
#define SHA256(input, len, output)       sha2(input, len, output, 0)
#else
#define SHA256(input, len, output)       sha2(input, (int)len, output, 0)
#endif /* POLARSSL_VERSION_NUMBER >= 0x00630500 */

#endif /* defined(POLARSSL_SHA256_C) */

/* Here stand the bindings for AES functions and contexts */
#define AES_CONTEXT                      aes_context
#define AES_SETENC_KEY(ctx, key, size)   aes_setkey_enc(ctx, key, size)
#define AES_SETDEC_KEY(ctx, key, size)   aes_setkey_dec(ctx, key, size)
#define AES_ECB_ENC(ctx, mode, in, out)  aes_crypt_ecb(ctx, mode, in, out)
#define AES_CBC(ctx, mode, size, iv, in, out) \
                                         aes_crypt_cbc(ctx, mode, size, iv, in, out);



#endif /* SSL_BINDINGS_H */
