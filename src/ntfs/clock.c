/* -*- coding: utf-8 -*- */
/* -*- mode: c -*- */
/*
 * Dislocker -- enables to read/write on BitLocker encrypted partitions under
 * Linux
 * Copyright (C) 2012  Romain Coltel, Hervé Schauer Consultants
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
#include "clock.h"


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


/**
 * Convert an UTF-16 string into a wchar_t string. wchar_t may be defined as
 * UTF-16 or UTF-32, this function doesn't care.
 * The UTF-32 string is supposed to be, at least, utf16_length*2 long
 * 
 * @param utf16 An UTF-16 string
 * @param utf16_length The UTF-16 string length
 * @param utf32 The wchar_t string resulted from the conversion
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int utf16towchars(uint16_t* utf16, size_t utf16_length, wchar_t* utf32)
{
	if(!utf16 || !utf32)
		return FALSE;
	
	memset(utf32, 0, utf16_length*2);
	
	size_t loop = 0;
	size_t nb_iter = utf16_length/2;
	
	for(loop = 0; loop < nb_iter; ++loop)
		utf32[loop] = utf16[loop];
	
	return TRUE;
}

