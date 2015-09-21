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

#include "dislocker/config.priv.h"
#include "dislocker/ntfs/clock.h"
#include "dislocker/metadata/guid.h"
#include "dislocker/metadata/datums.h"
#include "dislocker/metadata/extended_info.h"
#include "dislocker/metadata/metadata.h"


/*
 * Prototypes
 */

int get_vmk_from_bekfile(dis_metadata_t dis_meta, dis_config_t* cfg, void** vmk_datum);
int get_vmk_from_bekfile2(dis_metadata_t dis_meta, char* bek_file, void** vmk_datum);

int get_bek_dataset(int fd, void** bek_dataset);



#endif // READ_BEKFILE_H
