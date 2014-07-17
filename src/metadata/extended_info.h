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
#ifndef EXTENDED_INFO_H
#define EXTENDED_INFO_H

#include "common.h"




/**
 * This structure is new to Windows 8
 * It's the virtualization datum's payload
 */
typedef struct _extended_info {
	uint16_t unknown1;
	uint16_t size;
	uint32_t unknown2;
	uint64_t flags;
	uint64_t convertlog_addr;
	uint32_t convertlog_size;
	uint32_t sector_size1;
	uint32_t sector_size2;
} extended_info_t;




/*
 * Here are prototypes of functions dealing extended info
 */
void print_extended_info(LEVELS level, extended_info_t* xinfo);




#endif // EXTENDED_INFO_H
