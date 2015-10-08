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


#include "dislocker/metadata/guid.h"



/**
 * Some GUIDs found in BitLocker
 */
const guid_t INFORMATION_OFFSET_GUID = {
	0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a,
	0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01
};

const guid_t EOW_INFORMATION_OFFSET_GUID = {
	0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d,
	0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8
};




/**
 * Get raw GUID data and format it in a formated GUID
 *
 * @param raw_guid GUID directly extracted
 * @param formated_guid (out) A GUID ready to be printed (needs 37 bytes)
 */
void format_guid(uint8_t *raw_guid, char* formated_guid)
{
	int i, j;

	memset(formated_guid, 0, 37);

	for(i = 3, j = 0; i >= 0; i--, j += 2)
		sprintf(&formated_guid[j], "%.2X", raw_guid[i]);
	// 4*2 = 8

	sprintf(&formated_guid[j], "-"); j++;
	for(i = 5; i > 3; i--, j += 2)
		sprintf(&formated_guid[j], "%.2X", raw_guid[i]);
	// 13

	sprintf(&formated_guid[j], "-"); j++;
	for(i = 7; i > 5; i--, j += 2)
		sprintf(&formated_guid[j], "%.2X", raw_guid[i]);
	// 18

	sprintf(&formated_guid[j], "-"); j++;
	for(i = 8; i < 10; i++, j += 2)
		sprintf(&formated_guid[j], "%.2X", raw_guid[i]);
	// 23

	sprintf(&formated_guid[j], "-"); j++;
	for(i = 10; i < 16; i++, j += 2)
		sprintf(&formated_guid[j], "%.2X", raw_guid[i]);
	// 36... + 1 = 37
}


/**
 * Check if two guids match
 *
 * @param guid_1 The first guid to compare
 * @param guid_2 The second guid to compare
 * @return TRUE if match, FALSE otherwise
 */
int check_match_guid(guid_t guid_1, guid_t guid_2)
{
	return (
		guid_1[0] == guid_2[0] &&
		guid_1[1] == guid_2[1] &&
		guid_1[2] == guid_2[2] &&
		guid_1[3] == guid_2[3] &&
		guid_1[4] == guid_2[4] &&
		guid_1[5] == guid_2[5] &&
		guid_1[6] == guid_2[6] &&
		guid_1[7] == guid_2[7] &&
		guid_1[8] == guid_2[8] &&
		guid_1[9] == guid_2[9] &&
		guid_1[10] == guid_2[10] &&
		guid_1[11] == guid_2[11] &&
		guid_1[12] == guid_2[12] &&
		guid_1[13] == guid_2[13] &&
		guid_1[14] == guid_2[14] &&
		guid_1[15] == guid_2[15]
	);
}


#ifdef _HAVE_RUBY
static VALUE rb_format_guid(VALUE self, VALUE rb_vGuid)
{
	(void) self;
	char* guid = StringValuePtr(rb_vGuid);
	char formated_guid[37];

	format_guid((uint8_t*) guid, formated_guid);
	return rb_str_new(formated_guid, 37);
}

void Init_guid(VALUE rb_cDislockerMetadata)
{
	VALUE rb_mDisMetadataGuid = rb_define_module_under(rb_cDislockerMetadata, "GUID");
	VALUE offset_guids = rb_ary_new3(
		2,
		rb_str_new((const char*)INFORMATION_OFFSET_GUID, 16),
		rb_str_new((const char*)EOW_INFORMATION_OFFSET_GUID, 16)
	);

	rb_define_const(rb_mDisMetadataGuid, "INFORMATION_OFFSETS", offset_guids);
	rb_define_singleton_method(rb_mDisMetadataGuid, "pretty", rb_format_guid, 1);
}
#endif /* _HAVE_RUBY */
