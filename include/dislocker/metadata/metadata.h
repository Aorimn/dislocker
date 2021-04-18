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

#include <stdint.h>
#include "dislocker/dislocker.h"
#include "dislocker/metadata/metadata_config.h"




/** Known BitLocker versions */
enum {
	V_VISTA = 1,
	V_SEVEN = 2  // Same version used by Windows 8
};
typedef uint16_t version_t;


/**
 * Metadata structure to use to query the functions below
 */
typedef struct _dis_metadata* dis_metadata_t;





/*
 * Prototypes
 */
dis_metadata_t dis_metadata_new(dis_metadata_config_t dis_metadata_cfg);
dis_metadata_t dis_metadata_get(dis_context_t dis_ctx);

int dis_metadata_initialize(dis_metadata_t dis_metadata);

int dis_metadata_destroy(dis_metadata_t dis_metadata);


int check_state(dis_metadata_t dis_metadata);

void dis_metadata_vista_vbr_fve2ntfs(dis_metadata_t dis_meta, void* vbr);
void dis_metadata_vista_vbr_ntfs2fve(dis_metadata_t dis_meta, void* vbr);

int dis_metadata_is_overwritten(
	dis_metadata_t dis_metadata,
	off_t offset,
	size_t size
);

uint64_t dis_metadata_volume_size_from_vbr(dis_metadata_t dis_meta);

void* dis_metadata_set_dataset(
	dis_metadata_t dis_metadata,
	void* new_dataset
);

void* dis_metadata_set_volume_header(
	dis_metadata_t dis_metadata,
	void* new_volume_header
);

uint16_t dis_metadata_sector_size(dis_metadata_t dis_meta);

version_t dis_metadata_information_version(dis_metadata_t dis_meta);

uint64_t dis_metadata_encrypted_volume_size(dis_metadata_t dis_meta);

uint64_t dis_metadata_ntfs_sectors_address(dis_metadata_t dis_meta);
uint64_t dis_metadata_mftmirror(dis_metadata_t dis_meta);

uint32_t dis_metadata_backup_sectors_count(dis_metadata_t dis_meta);

int dis_metadata_is_decrypted_state(dis_metadata_t dis_meta);

#endif // METADATA_H
