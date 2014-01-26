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
#ifndef READ_BEKFILE_H
#define READ_BEKFILE_H

#include "ntfs/clock.h"
#include "ntfs/guid.h"
#include "metadata/datums.h"
#include "metadata/extended_info.h"





#pragma pack (1)
typedef struct _key_header
{
  uint16_t size;
  uint16_t zeros;
  datum_t datum_type;
  uint16_t error_status;
  cipher_t algorithm;
  uint8_t unknown1[2]; 
  uint8_t decryption_key[32]; // cle de decrypt: 256 bits
} key_header_t;


typedef struct _external_info_header
{
  /* total header size = 32 bytes (0x20) */
  uint16_t size;         // taille totale (header + payload)
  uint16_t unknown1;     // =0x0006
  datum_t datum_type;    // =0x0009 (external info)
  uint16_t error_status; // =0x0001
  
  uint8_t guid[16];
  ntfs_time_t timestamp;
  
} external_info_header_t;


typedef struct dataset_format 
{
  /* total header size = 48 bytes (0x30) */
  uint32_t size; // taille totale (header_size + payload)
  uint32_t unknown1; // = 0x01
  uint32_t header_size; // = headers size
  uint32_t size_copy; 
  
  uint8_t  hash[16]; // guid
  
  uint32_t next_counter;
  uint32_t algo_zeroed; // =0x0
  ntfs_time_t timestamp;
  
} dataset_t;
#pragma pack ()





/*
 * Prototypes
 */
void print_bek_header(dataset_t*);

void print_ext_info_header(external_info_header_t*);

void print_key(key_header_t*);

void decode(int, dataset_t*, external_info_header_t*, key_header_t*);

int get_bek_dataset(int fd, void** bek_dataset);



#endif // READ_BEKFILE_H
