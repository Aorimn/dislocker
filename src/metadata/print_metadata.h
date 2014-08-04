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
#ifndef PRINT_METADATA_H
#define PRINT_METADATA_H

#include "common.h"
#include "metadata.h"
#include "datums.h"


void print_volume_header(LEVELS level, volume_header_t *volume_header);

void print_bl_metadata(LEVELS level, bitlocker_header_t *bl_header);

void print_eow_infos(LEVELS level, bitlocker_eow_infos_t *eow_infos);

void print_dataset(LEVELS level, bitlocker_dataset_t* dataset);

void print_data(LEVELS level, void* metadata);

const char* get_bl_state(state_t state);


#endif // PRINT_METADATA_H
