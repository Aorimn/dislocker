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

#include "dislocker/encryption/encommon.h"


/**
 * Create "an object" of type dis_crypt_t
 * 
 * @param sector_size The sector size is needed for various operations. It's the
 * size to be used for decrypting the disc as it's encrypted sector by sector.
 * @param use_diffuser Indicate the encryption is using the diffuser (TRUE or
 * FALSE).
 * @return The newly allocated dis_crypt_t "object".
 */
dis_crypt_t dis_crypt_new(uint16_t sector_size, int use_diffuser)
{
	dis_crypt_t crypt = xmalloc(sizeof(struct _dis_crypt));
	memset(crypt, 0, sizeof(struct _dis_crypt));
	crypt->sector_size = sector_size;
	if(use_diffuser == TRUE)
		crypt->flags |= DIS_ENC_FLAG_USE_DIFFUSER;
	
	return crypt;
}

dis_aes_contexts_t* dis_crypt_aes_contexts(dis_crypt_t crypt)
{
	return &crypt->ctx;
}

void dis_crypt_destroy(dis_crypt_t crypt)
{
	if(crypt)
		xfree(crypt);
}
