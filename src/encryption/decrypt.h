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
#ifndef DECRYPT_H
#define DECRYPT_H


#define AUTHENTICATOR_LENGTH 16


#include "encommon.h"
#include "metadata/datums.h"




/*
 * Prototypes
 */
int decrypt_key(datum_aes_ccm_t* input, unsigned char* key, void** output, unsigned int* output_size);

int decrypt_sector(dis_iodata_t* global_data, uint8_t* sector, off_t sector_address, uint8_t* buffer);



#endif /* DECRYPT_H */

