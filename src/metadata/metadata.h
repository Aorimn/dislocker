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
#ifndef METADATA_H
#define METADATA_H


#include "common.h"
#include "config.h"
#include "ntfs/clock.h"
#include "ntfs/guid.h"


/** Known BitLocker versions */
enum {
	V_VISTA = 1,
	V_SEVEN = 2  // Same version used by Windows 8
};
typedef uint16_t version_t;



/** Different first sectors of an NTFS or BitLocker Vista/Seven partition */
#pragma pack (1)
typedef struct _volume_header
{
	/* 512 bytes long */
	uint8_t  jump[3];             //                                                -- offset 0
	uint8_t  signature[8];        // = "-FVE-FS-" (without 0 at the string's end)   -- offset 3
	                              // = "NTFS    " (idem) for NTFS volumes (ORLY?)
	
	uint16_t sector_size;         // = 0x0200 = 512 bytes                           -- offset 0xb
	uint8_t  sectors_per_cluster; //                                                -- offset 0xd
	uint16_t reserved_clusters;   //                                                -- offset 0xe
	uint8_t  fat_count;           //                                                -- offset 0x10
	uint16_t root_entries;        //                                                -- offset 0x11
	uint16_t nb_sectors_16b;      //                                                -- offset 0x13
	uint8_t  media_descriptor;    //                                                -- offset 0x15
	uint16_t sectors_per_fat;     //                                                -- offset 0x16
	uint16_t sectors_per_track;   //                                                -- offset 0x18
	uint16_t nb_of_heads;         //                                                -- offset 0x1a
	uint32_t hidden_sectors;      //                                                -- offset 0x1c
	uint32_t nb_sectors_32b;      //                                                -- offset 0x20
	uint8_t  unknown2[4];         // For NTFS, always 0x00800080 (little endian)    -- offset 0x24
	uint64_t nb_sectors_64b;      //                                                -- offset 0x28
	uint64_t mft_start_cluster;   //                                                -- offset 0x30
	union {                       // Metadata LCN or MFT Mirror                     -- offset 0x38
		uint64_t metadata_lcn;    //  depending on whether we're talking about a Vista volume
		uint64_t mft_mirror;      //  or an NTFS one
	};
	uint8_t  unknown3[96];        // FIXME                                          -- offset 0x40
	
	guid_t   guid;                //                                                -- offset 0xa0
	uint64_t offset_bl_header[3]; // NOT for Vista                                  -- offset 0xb0
	
	
	uint8_t  unknown4[310];       // FIXME                                          -- offset 0xc8
	
	uint16_t boot_partition_identifier; // = 0xaa55                                 -- offset 0x1fe
} volume_header_t; // Size = 512
#pragma pack ()



#pragma pack (1)
typedef struct _bitlocker_dataset
{
	uint32_t size;         //                      -- offset 0
	uint32_t unknown1;     // = 0x0001 FIXME       -- offset 4
	uint32_t header_size;  // = 0x0030             -- offset 8
	uint32_t copy_size;    // = dataset_size       -- offset 0xc
	
	guid_t guid;           // dataset GUID         -- offset 0x10
	uint32_t next_counter; //                      -- offset 0x20
	
	uint16_t algorithm;    //                      -- offset 0x24
	uint16_t trash;        //                      -- offset 0x26
	ntfs_time_t timestamp; //                      -- offset 0x28
} bitlocker_dataset_t; // Size = 0x30
#pragma pack ()



#pragma pack (1)
typedef struct _bitlocker_header
{
	uint8_t signature[8]; // = "-FVE-FS-"                                                   -- offset 0
	uint16_t size;        // Total size (has to be multiplied by 16 when the version is 2)  -- offset 8
	version_t version;    // = 0x0002 for Windows 7 and 1 for Windows Vista                 -- offset 0xa
	
	uint8_t unknown1[4];  // FIXME Unknown -- What else?                                    -- offset 0xc
	uint64_t encrypted_volume_size; // Size of the encrypted volume                         -- offset 0x10
	uint8_t unknown2[4];  //                                                                -- offset 0x18
	uint32_t nb_backup_sectors;   //                                                        -- offset 0x1c
	
	uint64_t offset_bl_header[3]; //                                                        -- offset 0x20
	
	uint64_t boot_sectors_backup; // Address where the boot sectors have been backed up     -- offset 0x38
	                              // This is the address of the MftMirror for Vista
	
	struct _bitlocker_dataset dataset; // See above                                         -- offset 0x40
} bitlocker_header_t; // Size = 0x40 + 0x30
#pragma pack ()



#pragma pack (1)
typedef struct _bitlocker_validations_infos
{
	uint16_t  size;
	version_t version;
	uint32_t  crc32;
} bitlocker_validations_infos_t;
#pragma pack ()




#include "datums.h"




/*
 * Prototypes
 */
int get_volume_header(volume_header_t *volume_header, int fd, off_t partition_offset);

void print_volume_header(LEVELS level, volume_header_t *volume_header);

int get_metadata(off_t source, void **metadata, int fd);

void print_bl_metadata(LEVELS level, bitlocker_header_t *bl_header);

int get_dataset(void* metadata, bitlocker_dataset_t** dataset);

void print_data(LEVELS level, void* metadata);

int get_metadata_check_validations(volume_header_t* volume_header, int fd, void** metadata, dis_config_t* cfg);

int has_clear_key(void* dataset, datum_vmk_t** vmk_datum);


#include "vmk.h"


#endif // METADATA_H
