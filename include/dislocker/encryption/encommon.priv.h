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
#ifndef ENCOMMON_PRIV_H
#define ENCOMMON_PRIV_H


#include "dislocker/encryption/encommon.h"

#include "dislocker/ssl_bindings.h"



/**
 * AES contexts "used" during encryption/decryption
 * @see encryption/decrypt.c
 * @see encryption/encrypt.c
 */
struct _aes_contexts {
	AES_CONTEXT FVEK_E_ctx;
	AES_CONTEXT FVEK_D_ctx;

	AES_CONTEXT TWEAK_E_ctx;
	AES_CONTEXT TWEAK_D_ctx; /* useless, never used */
};



typedef enum {
	DIS_ENC_FLAG_USE_DIFFUSER = (1 << 0)
} dis_enc_flags_e;

struct _dis_crypt {
	struct _aes_contexts ctx;

	dis_enc_flags_e flags;

	uint16_t sector_size;

	void (*decrypt_fn)(
		dis_aes_contexts_t* ctx,
		uint16_t sector_size,
		uint8_t* sector,
		off_t sector_address,
		uint8_t* buffer
	);
	void (*encrypt_fn)(
		dis_aes_contexts_t* ctx,
		uint16_t sector_size,
		uint8_t* sector,
		off_t sector_address,
		uint8_t* buffer
	);
};



#endif /* ENCOMMON_PRIV_H */
