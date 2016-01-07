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
#ifndef DIS_METADATA_PRIV_H
#define DIS_METADATA_PRIV_H


#include "dislocker/common.h"
#include "dislocker/metadata/metadata.h"
#include "dislocker/metadata/extended_info.h"
#include "dislocker/metadata/guid.h"
#include "dislocker/ntfs/clock.h"

#include "dislocker/return_values.h"
#define checkupdate_dis_meta_state(ctx, state)                              \
	do {                                                                    \
		(ctx)->curr_state = (state);                                        \
		if((state) == (ctx)->init_stop_at) {                                \
			dis_printf(L_DEBUG, "Library end init at state %d\n", (state)); \
			return (state);                                                 \
		}                                                                   \
	} while(0);

#include <assert.h>

#ifndef static_assert
#define static_assert(x, s) extern int static_assertion[2*!!(x)-1]
#endif



#pragma pack (1)
/** First sector of an NTFS or BitLocker volume */
typedef struct _volume_header
{
	/* 512 bytes long */
	uint8_t  jump[3];             //                                                -- offset 0
	uint8_t  signature[8];        // = "-FVE-FS-" (without 0 at the string's end)   -- offset 3
	                              // = "NTFS    " (idem) for NTFS volumes (ORLY?)
	                              // = "MSWIN4.1" for BitLocker-To-Go encrypted volumes

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

	union {                       //                                                -- offset 0x24
		struct { // Classic BitLocker
			uint8_t  unknown2[4];         // NTFS = 0x00800080 (little endian)
			uint64_t nb_sectors_64b;      //                                        -- offset 0x28
			uint64_t mft_start_cluster;   //                                        -- offset 0x30
			union {                       // Metadata LCN or MFT Mirror             -- offset 0x38
				uint64_t metadata_lcn;    //  depending on whether we're talking about a Vista volume
				uint64_t mft_mirror;      //  or an NTFS one
			};
			uint8_t  unknown3[96];        //                                        -- offset 0x40

			guid_t   guid;                //                                        -- offset 0xa0
			uint64_t information_off[3];  // NOT for Vista                          -- offset 0xb0
			uint64_t eow_information_off[2]; // NOT for Vista NOR 7                 -- offset 0xc8

			uint8_t  unknown4[294];       //                                        -- offset 0xd8
		};
		struct { // BitLocker-To-Go
			uint8_t  unknown5[35];

			uint8_t  fs_name[11];         //                                        -- offset 0x47
			uint8_t  fs_signature[8];     //                                        -- offset 0x52

			uint8_t  unknown6[334];       //                                        -- offset 0x5a

			guid_t   bltg_guid;           //                                        -- offset 0x1a8
			uint64_t bltg_header[3];      //                                        -- offset 0x1b8

			uint8_t  Unknown7[46];        //                                        -- offset 0x1d0
		};
	};

	uint16_t boot_partition_identifier; // = 0xaa55                                 -- offset 0x1fe
} volume_header_t; // Size = 512

static_assert(
	sizeof(struct _volume_header) == 512,
	"Volume header structure's size isn't equal to 512"
);



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

static_assert(
	sizeof(struct _bitlocker_dataset) == 0x30,
	"BitLocker dataset structure's size isn't equal to 0x30"
);


/** Different states BitLocker is in */
enum state_types
{
	METADATA_STATE_NULL                     = 0,
	METADATA_STATE_DECRYPTED                = 1,
	METADATA_STATE_SWITCHING_ENCRYPTION     = 2,
	METADATA_STATE_EOW_ACTIVATED            = 3,
	METADATA_STATE_ENCRYPTED                = 4,
	METADATA_STATE_SWITCH_ENCRYPTION_PAUSED = 5
};
typedef uint16_t dis_metadata_state_t;


/**
 * Header of a BitLocker metadata structure, named information
 *
 * Datums (protectors) with keys in them follow this header
 */
typedef struct _bitlocker_information
{
	uint8_t signature[8]; // = "-FVE-FS-"                                                   -- offset 0
	uint16_t size;        // Total size (has to be multiplied by 16 when the version is 2)  -- offset 8
	version_t version;    // = 0x0002 for Windows 7 and 1 for Windows Vista                 -- offset 0xa

	/* Not sure about the next two fields */
	dis_metadata_state_t curr_state;  // Current encryption state                           -- offset 0xc
	dis_metadata_state_t next_state;  // Next encryption state                              -- offset 0xe

	uint64_t encrypted_volume_size; // Size of the encrypted volume                         -- offset 0x10
	/*
	 * The following size describes a virtualized region. This region is only
	 * checked when this->curr_state == 2. It begins at the offset described by
	 * this->encrypted_volume_size
	 */
	uint32_t convert_size;  //                                                              -- offset 0x18
	uint32_t nb_backup_sectors;   //                                                        -- offset 0x1c

	uint64_t information_off[3];  //                                                        -- offset 0x20

	union {
		uint64_t boot_sectors_backup; // Address where the boot sectors have been backed up -- offset 0x38
		uint64_t mftmirror_backup;    // This is the address of the MftMirror for Vista     -- offset 0x38
	};

	struct _bitlocker_dataset dataset; // See above                                         -- offset 0x40
} bitlocker_information_t; // Size = 0x40 + 0x30

static_assert(
	sizeof(struct _bitlocker_information) == (0x40 + 0x30),
	"BitLocker information structure's size isn't equal to 0x70"
);



/*
 * The following structure is followed by a datum of type 5 (DATUM_AES_CCM) or 1
 * (DATUM_KEY). When there's a DATUM_AES_CCM, this is actually the DATUM_KEY
 * encrypted using the VMK.
 * The key contained in the DATUM_KEY structure is the SHA-256 sum of the entire
 * BitLocker's metadata fields (bitlocker_information_t + every datum).
 *
 * Therefore, the size field contains 8 plus the size of the datum.
 */
typedef struct _bitlocker_validations
{
	uint16_t  size;
	version_t version;
	uint32_t  crc32;
} bitlocker_validations_t; // Size = 8

static_assert(
	sizeof(struct _bitlocker_validations) == 8,
	"BitLocker validations structure's size isn't equal to 8"
);



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

static_assert(
	sizeof(struct _bitlocker_eow_infos) == 0x38,
	"BitLocker EOW information structure's size isn't equal to 0x38"
);

#pragma pack ()




/**
 * A region is used to describe BitLocker metadata on disk
 */
typedef struct _regions
{
	/* Metadata offset */
	uint64_t addr;
	/* Metadata size on disk */
	uint64_t size;
} dis_regions_t;



struct _dis_metadata {
	/* The volume header, 512 bytes */
	volume_header_t* volume_header;

	/* BitLocker-volume's main metadata */
	bitlocker_information_t* information;

	/* BitLocker-volume's submain metadata */
	bitlocker_dataset_t* dataset;

	/* BitLocker-volume's EOW main metadata */
	bitlocker_eow_infos_t* eow_information;

	/*
	 * Virtualized regions are presented as zeroes when queried from the NTFS
	 * layer. In these virtualized regions, we find the 3 BitLocker metadata
	 * headers, the area where NTFS boot sectors are backed-up for W$ 7&8, and
	 * an area I don't know about yet for W$ 8.
	 * This last area is used only when BitLocker's state is 2.
	 */
	size_t           nb_virt_region;
	dis_regions_t    virt_region[5];

	/* Size (in bytes) of the NTFS backed-up sectors */
	off_t            virtualized_size;

	/* Extended info which may be present (NULL otherwise) */
	extended_info_t* xinfo;

	/* A pointer to the configuration of the metadata */
	dis_metadata_config_t cfg;
};


#ifdef _HAVE_RUBY
#include "dislocker/ruby.h"

void Init_metadata(VALUE rb_mDislocker);
#endif

#endif /* DIS_METADATA_PRIV_H */
