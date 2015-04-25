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
#ifndef PREPARE_H
#define PREPARE_H


#include <stdint.h>

#include "dislocker/dislocker.priv.h"
#include "dislocker/encryption/encommon.h"
#include "dislocker/metadata/datums.h"
#include "dislocker/metadata/metadata.h"



/**
 * Function used to initialize keys used for decryption/encryption
 */
int init_keys(bitlocker_dataset_t* dataset, datum_key_t* fvek, dis_crypt_t crypt);

/**
 * Function used to prepare a structure which hold data used for
 * decryption/encryption
 */
int prepare_crypt(dis_context_t dis_ctx);


#endif /* PREPARE_H */
