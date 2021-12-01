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
#ifndef GUID_H
#define GUID_H


#include "dislocker/common.h"


// GUID type = array of 16 unsigned bytes
typedef uint8_t guid_t[16];


/*
 * Prototypes
 */
void format_guid(uint8_t *raw_guid, char* formated_guid);

int check_match_guid(guid_t guid_1, guid_t guid_2);

#ifdef _HAVE_RUBY
#include "dislocker/ruby.h"

void Init_guid(VALUE rb_mDislockerMetadata);
#endif


#endif // GUID_H
