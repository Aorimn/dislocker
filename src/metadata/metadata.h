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
#include "guid.h"
#include "ntfs/clock.h"


/** Known BitLocker versions */
enum {
	V_VISTA = 1,
	V_SEVEN = 2  // Same version used by Windows 8
};
typedef uint16_t version_t;



#pragma pack (1)
/** First sector of an NTFS or BitLocker volume */
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
	uint64_t offset_eow_information[2]; // NOT for Vista nor 7                      -- offset 0xc8
	
	uint8_t  unknown4[294];       // FIXME                                          -- offset 0xd8
	
	uint16_t boot_partition_identifier; // = 0xaa55                                 -- offset 0x1fe
} volume_header_t; // Size = 512



/** Header of a data set, used in the bitlocker header below */
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


/** Different states BitLocker is in */
enum state_types
{
	DECRYPTED                = 1,
	SWITCHING_ENCRYPTION     = 2,
	ENCRYPTED                = 4,
	SWITCH_ENCRYPTION_PAUSED = 5
};
typedef uint16_t state_t;


/**
 * Header of a BitLocker metadata structure
 * 
 * Datums (protectors) with keys in them follow this header
 */
typedef struct _bitlocker_header
{
	uint8_t signature[8]; // = "-FVE-FS-"                                                   -- offset 0
	uint16_t size;        // Total size (has to be multiplied by 16 when the version is 2)  -- offset 8
	version_t version;    // = 0x0002 for Windows 7 and 1 for Windows Vista                 -- offset 0xa
	
	/* Not sure about the next two fields */
	state_t curr_state;  // Current encryption state                                        -- offset 0xc
	state_t next_state;  // Next encryption state                                           -- offset 0xe
	
	uint64_t encrypted_volume_size; // Size of the encrypted volume                         -- offset 0x10
	/*
	 * This size describe a virtualized region. This region is only checked when
	 * this->curr_state == 2. It begins at the offset described by
	 * this->encrypted_volume_size
	 */
	uint32_t unknown_size;  //                                                              -- offset 0x18
	uint32_t nb_backup_sectors;   //                                                        -- offset 0x1c
	
	uint64_t offset_bl_header[3]; //                                                        -- offset 0x20
	
	union {
		uint64_t boot_sectors_backup; // Address where the boot sectors have been backed up -- offset 0x38
		uint64_t mftmirror_backup;    // This is the address of the MftMirror for Vista     -- offset 0x38
	};
	
	struct _bitlocker_dataset dataset; // See above                                         -- offset 0x40
} bitlocker_header_t; // Size = 0x40 + 0x30



/*
 * The following structure is followed by a datum of type 5 (DATUM_AES_CCM) or 1
 * (DATUM_KEY). When there's a DATUM_AES_CCM, this is actually the DATUM_KEY
 * encrypted using the VMK.
 * The key contained in the DATUM_KEY structure is the SHA-256 sum of the entire
 * BitLocker's metadata fields (bitlocker_header_t + every datum).
 * 
 * Therefore, the size field contains 8 plus the size of the datum.
 */
typedef struct _bitlocker_validations_infos
{
	uint16_t  size;
	version_t version;
	uint32_t  crc32;
} bitlocker_validations_infos_t; // Size = 8



/**
 * The following structure is used when the volume GUID is
 * EOW_INFORMATION_OFFSET_GUID (see guid.c).
 * It's followed by some kind of payload I don't know about yet (but that
 * explains header_size vs infos_size)
 */
typedef struct _bitlocker_eow_infos
{
	uint8_t  signature[8];    // = "FVE-EOW"                                    -- offset 0
	uint16_t header_size;     // = 0x38                                         -- offset 8
	uint16_t infos_size;      //                                                -- offset 0xa
	uint32_t sector_size1;    //                                                -- offset 0xc
	uint32_t sector_size2;    //                                                -- offset 0x10
	uint32_t unknown_14;      // FIXME                                          -- offset 0x14
	uint32_t convlog_size;    //                                                -- offset 0x18
	uint32_t unknown_1c;      // FIXME                                          -- offset 0x1c
	uint32_t nb_regions;      //                                                -- offset 0x20
	uint32_t crc32;           //                                                -- offset 0x24
	uint64_t disk_offsets[2]; //                                                -- offset 0x28
} bitlocker_eow_infos_t; // Size = 0x38


#pragma pack ()




/*
 * Prototypes
 */
int get_volume_header(volume_header_t *volume_header, int fd, off_t partition_offset);

int get_metadata(off_t source, void **metadata, int fd);

int get_dataset(void* metadata, bitlocker_dataset_t** dataset);

int get_eow_information(off_t source, void** eow_infos, int fd);

int get_metadata_check_validations(volume_header_t* volume_header, int fd, void** metadata, dis_config_t* cfg);

int get_eow_check_valid(volume_header_t *volume_header, int fd, void **eow_infos, dis_config_t* cfg);

int check_state(bitlocker_header_t* metadata);


#endif // METADATA_H
