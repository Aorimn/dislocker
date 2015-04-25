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

#include "dislocker/ntfs/encoding.h"


/**
 * Convert an UTF-16 string into a wchar_t string. wchar_t may be defined as
 * UTF-16 or UTF-32, this function doesn't care.
 * The UTF-32 string is supposed to be, at least, utf16_length*2 long.
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

/**
 * Convert an ascii null-terminated string into an UTF-16 null-terminated
 * string.
 * The UTF-16 string is supposed to be, at least, (strlen(ascii)+1)*2 long.
 *
 * @param ascii A null-terminated ascii string
 * @param utf16 The UTF-16 string resulted from the conversion
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int asciitoutf16(const uint8_t* ascii, uint16_t* utf16)
{
	if(!ascii || !utf16)
		return FALSE;

	size_t len = strlen((char*)ascii);
	memset(utf16, 0, (len+1)*2);

	size_t loop = 0;
	for(loop = 0; loop < len; loop++)
		utf16[loop] = ascii[loop];

	return TRUE;
}
