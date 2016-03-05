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
#ifndef DIS_AES_XTS_H
#define DIS_AES_XTS_H

#include "dislocker/ssl_bindings.h"


/*
 * Prototypes
 */
int dis_aes_crypt_xex(
	AES_CONTEXT *crypt_ctx,
	AES_CONTEXT *tweak_ctx,
	int mode,
	size_t length,
	unsigned char *iv,
	const unsigned char *input,
	unsigned char *output
);
int dis_aes_crypt_xts(
	AES_CONTEXT *crypt_ctx,
	AES_CONTEXT *tweak_ctx,
	int mode,
	size_t length,
	unsigned char *iv,
	const unsigned char *input,
	unsigned char *output
);

#endif /* DIS_AES_XTS_H */
