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
#include "dislocker/ntfs/clock.h"


// Constant used to convert NTFS timestamp into a UTC one
#define NTFS_TIME_OFFSET  ((ntfs_time_t)(369 * 365 + 89) *24 * 3600 * 10000000)

/**
 * Convert a ntfs timestamp into a utc one
 *
 * @param t NTFS timestamp
 * @param ts UTC timestamp
 */
void ntfs2utc(ntfs_time_t t, time_t *ts)
{
	if (ts == NULL)
		return;

	*ts = (time_t) ((t - (uint64_t)(NTFS_TIME_OFFSET)) / (uint64_t)10000000 );
}
