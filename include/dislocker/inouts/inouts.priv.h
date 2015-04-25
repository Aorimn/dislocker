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
#ifndef DIS_INOUTS_PRIV_H
#define DIS_INOUTS_PRIV_H

#include <pthread.h>

#include "dislocker/inouts/inouts.h"
#include "dislocker/metadata/datums.h"
#include "dislocker/metadata/metadata.h"
#include "dislocker/encryption/encommon.h"




/**
 * Structure used for operation on disk (encryption/decryption)
 */
struct _data {
	/* The metadata structure object */
	dis_metadata_t metadata;

	/* The VMK */
	datum_key_t*   vmk;

	/* The FVEK */
	datum_key_t*   fvek;

	/* Where the real partition begins */
	off_t          part_off;
	/* Volume sector size */
	uint16_t       sector_size;
	/* Volume size, in bytes */
	uint64_t       volume_size;
	/* File descriptor to access the volume */
	int            volume_fd;

	/* Size of the encrypted part of the volume */
	uint64_t       encrypted_volume_size;
	union {
		/* Address of the NTFS sectors backuped */
		uint64_t   backup_sectors_addr;
		/* MFTMirror field */
		uint64_t   mftmirror_backup;
	};
	/* Number of NTFS sectors backuped */
	uint32_t       nb_backup_sectors;

	/* Structure used to encrypt or decrypt */
	dis_crypt_t    crypt;

	/* Volume's state is kept here */
	int            volume_state;

	/* Function to decrypt a region of the volume */
	int(*decrypt_region)(
		struct _data* io_data,
		size_t nb_read_sector,
		uint16_t sector_size,
		off_t sector_start,
		uint8_t* output
	);
	/* Function to encrypt a region of the volume */
	int(*encrypt_region)(
		struct _data* io_data,
		size_t nb_write_sector,
		uint16_t sector_size,
		off_t sector_start,
		uint8_t* input
	);
};

#endif /* DIS_INOUTS_PRIV_H */
