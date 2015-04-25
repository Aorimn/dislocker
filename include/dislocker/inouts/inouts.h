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
#ifndef DIS_INOUTS_H
#define DIS_INOUTS_H

#include <stdint.h>

#include "dislocker/dislocker.h"

/**
 * Structure used for operation on disk (encryption/decryption)
 */
typedef struct _data dis_iodata_t;



/**
 * Function to get the volume's size
 */
uint64_t dis_inouts_volume_size(dis_context_t dis_ctx);

/**
 * Function to get the volume's sector size
 */
uint16_t dis_inouts_sector_size(dis_context_t dis_ctx);


#endif /* DIS_INOUTS_H */
