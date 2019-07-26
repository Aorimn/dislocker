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
#ifndef DATUM_HEADER_H
#define DATUM_HEADER_H


#include "dislocker/common.h"
#include "dislocker/metadata/metadata.h"
#include "dislocker/metadata/extended_info.h"
#include "dislocker/metadata/guid.h"
#include "dislocker/ntfs/clock.h"
#include "dislocker/ntfs/encoding.h"
#include "dislocker/encryption/encommon.h"

#include <assert.h>

#ifndef static_assert
#define static_assert(x, s) extern int static_assertion[2*!!(x)-1]
#endif


/**
 * Here stand datums' value types stuff
 */
#define NB_DATUMS_VALUE_TYPES 22

enum value_types
{
	/*  0 */ DATUMS_VALUE_ERASED = 0x0000,
	/*  1 */ DATUMS_VALUE_KEY,
	/*  2 */ DATUMS_VALUE_UNICODE,
	/*  3 */ DATUMS_VALUE_STRETCH_KEY,
	/*  4 */ DATUMS_VALUE_USE_KEY,
	/*  5 */ DATUMS_VALUE_AES_CCM,
	/*  6 */ DATUMS_VALUE_TPM_ENCODED,
	/*  7 */ DATUMS_VALUE_VALIDATION,
	/*  8 */ DATUMS_VALUE_VMK,
	/*  9 */ DATUMS_VALUE_EXTERNAL_KEY,
	/* 10 */ DATUMS_VALUE_UPDATE,
	/* 11 */ DATUMS_VALUE_ERROR,

	/* Below is only available on Windows Seven */
	/* 12 */ DATUMS_VALUE_ASYM_ENC,
	/* 13 */ DATUMS_VALUE_EXPORTED_KEY,
	/* 14 */ DATUMS_VALUE_PUBLIC_KEY,
	/* 15 */ DATUMS_VALUE_VIRTUALIZATION_INFO,
	/* 16 */ DATUMS_VALUE_SIMPLE_1,
	/* 17 */ DATUMS_VALUE_SIMPLE_2,
	/* 18 */ DATUMS_VALUE_CONCAT_HASH_KEY,
	/* 19 */ DATUMS_VALUE_SIMPLE_3
};
typedef uint16_t dis_datums_value_type_t;


/* Here are some specifics entry types (second field of the safe header) */
#define NB_DATUMS_ENTRY_TYPES 12

enum entry_types
{
	DATUMS_ENTRY_UNKNOWN1 = 0x0000,
	DATUMS_ENTRY_UNKNOWN2,
	DATUMS_ENTRY_VMK,
	DATUMS_ENTRY_FVEK,
	DATUMS_ENTRY_UNKNOWN3,
	DATUMS_ENTRY_UNKNOWN4,
	DATUMS_ENTRY_STARTUP_KEY,
	DATUMS_ENTRY_ENCTIME_INFORMATION,
	DATUMS_ENTRY_UNKNOWN7,
	DATUMS_ENTRY_UNKNOWN8,
	DATUMS_ENTRY_UNKNOWN9,
	DATUMS_ENTRY_UNKNOWN10,
	DATUMS_ENTRY_FVEK_2
};
typedef uint16_t dis_datums_entry_type_t;



/**
 * This is the minimal header a datum has
 */
#pragma pack (1)
typedef struct _header_safe
{
	uint16_t datum_size;
	dis_datums_entry_type_t entry_type;
	dis_datums_value_type_t value_type;
	uint16_t error_status;
} datum_header_safe_t;

static_assert(
	sizeof(struct _header_safe) == 8,
	"Datum header structure's size isn't equal to 8"
);





/**
 * Used if the datum header is not implemented yet, according to the datum type
 */
typedef struct _datum_generic
{
	datum_header_safe_t header;
// 	uint8_t* payload;
} datum_generic_type_t;



/**
 * Here are datum headers, according to their datum type
 */

/* Datum type = 0 */
typedef struct _datum_erased
{
	datum_header_safe_t header;
} datum_erased_t;


/* Datum type = 1 */
typedef struct _datum_key
{
	datum_header_safe_t header;
	cipher_t algo;
	uint16_t padd;
} datum_key_t;


/* Datum type = 2 */
typedef struct _datum_unicode
{
	datum_header_safe_t header;
} datum_unicode_t;


/* Datum type = 3 */
typedef struct _datum_stretch_key
{
	datum_header_safe_t header;
	cipher_t algo;
	uint16_t padd;
	uint8_t  salt[16];
} datum_stretch_key_t;


/* Datum type = 4 */
typedef struct _datum_use_key
{
	datum_header_safe_t header;
	cipher_t algo;
	uint16_t padd;
} datum_use_key_t;


/* Datum type = 5 */
typedef struct _datum_aes_ccm
{
	datum_header_safe_t header;
	uint8_t nonce[12];
	uint8_t mac[16];
} datum_aes_ccm_t;


/* Datum type = 6 */
typedef struct _datum_tpm_enc
{
	datum_header_safe_t header;
	uint32_t unknown;           // See properties below, the header size of this datum is 0xc => header + int32 (int32 possibly divided into more members)
} datum_tpm_enc_t;


/* Datum type = 8 */
typedef struct _datum_vmk
{
	datum_header_safe_t header;
	guid_t guid;
	uint8_t nonce[12];
} datum_vmk_t;


/* Datum type = 9 */
typedef struct _datum_external
{
	datum_header_safe_t header;
	guid_t guid;
	ntfs_time_t timestamp;
} datum_external_t;


/* Datum type = 15 */
typedef struct _datum_virtualization
{
	datum_header_safe_t header;
	uint64_t ntfs_boot_sectors;
	uint64_t nb_bytes;

	/*
	 * Below is a structure added to this virtualization structure in Windows 8
	 * The header is still 0x18 in size, which means xinfo is a payload
	 */
	extended_info_t xinfo;
} datum_virtualization_t;
#pragma pack ()







/**
 * A hardcoded table defining some properties for each datum
 */
typedef struct _datum_value_types_properties
{
	/*
	 * The header size of the datum, this is including the datum_header_safe_t
	 * structure which is beginning each one of them
	 */
	uint16_t size_header;

	/*
	 * A flag which tells us if the datum has one or more nested datum
	 * 0 = No nested datum
	 * 1 = One or more nested datum
	 */
	uint8_t has_nested_datum;

	/* Always equal to 0, maybe for padding */
	uint8_t zero;
} value_types_properties_t;

static const value_types_properties_t datum_value_types_prop[] =
{
	{ 8,    0, 0 },  // ERASED
	{ 0xc,  0, 0 },  // KEY
	{ 8,    0, 0 },  // UNICODE
	{ 0x1c, 1, 0 },  // STRETCH
	{ 0xc,  1, 0 },  // USE KEY
	{ 0x24, 0, 0 },  // AES CCM
	{ 0xc,  0, 0 },  // TPM ENCODED
	{ 8,    0, 0 },  // VALIDATION
	{ 0x24, 1, 0 },  // VMK
	{ 0x20, 1, 0 },  // EXTERNAL KEY
	{ 0x2c, 1, 0 },  // UPDATE
	{ 0x34, 0, 0 },  // ERROR

	/* These ones below were added for Seven */
	{ 8,    0, 0 },  // ASYM ENC
	{ 8,    0, 0 },  // EXPORTED KEY
	{ 8,    0, 0 },  // PUBLIC KEY
	{ 0x18, 0, 0 },  // VIRTUALIZATION INFO
	{ 0xc,  0, 0 },  // SIMPLE
	{ 0xc,  0, 0 },  // SIMPLE
	{ 0x1c, 0, 0 },  // CONCAT HASH KEY
	{ 0xc,  0, 0 }   // SIMPLE
};









/*
 * Here are prototypes of functions dealing with data
 */
char* cipherstr(cipher_t enc);
char* datumvaluetypestr(dis_datums_value_type_t value_type);

int get_header_safe(void* data, datum_header_safe_t* header);

int get_payload_safe(void* data, void** payload, size_t* size_payload);

void print_one_datum(DIS_LOGS level, void* datum);

void print_header(DIS_LOGS level, datum_header_safe_t* header);

void print_datum_generic(DIS_LOGS level, void* vdatum);
void print_datum_erased(DIS_LOGS level, void* vdatum);
void print_datum_key(DIS_LOGS level, void* vdatum);
void print_datum_unicode(DIS_LOGS level, void* vdatum);
void print_datum_stretch_key(DIS_LOGS level, void* vdatum);
void print_datum_use_key(DIS_LOGS level, void* vdatum);
void print_datum_aes_ccm(DIS_LOGS level, void* vdatum);
void print_datum_tpmenc(DIS_LOGS level, void* vdatum);
void print_datum_vmk(DIS_LOGS level, void* vdatum);
void print_datum_external(DIS_LOGS level, void* vdatum);
void print_datum_virtualization(DIS_LOGS level, void* vdatum);

void print_nonce(DIS_LOGS level, uint8_t* nonce);
void print_mac(DIS_LOGS level, uint8_t* mac);

int get_next_datum(
	dis_metadata_t dis_metadata,
	dis_datums_entry_type_t entry_type,
	dis_datums_value_type_t value_type,
	void* datum_begin,
	void** datum_result
);

int get_nested_datum(void* datum, void** datum_nested);
int get_nested_datumvaluetype(void* datum, dis_datums_value_type_t value_type, void** datum_nested);

int datum_value_type_must_be(void* datum, dis_datums_value_type_t value_type);

int dis_metadata_has_clear_key(dis_metadata_t dis_meta, void** vmk_datum);


typedef void(*print_datum_f)(DIS_LOGS, void*);
static const print_datum_f print_datum_tab[NB_DATUMS_VALUE_TYPES] =
{
	print_datum_erased,
	print_datum_key,
	print_datum_unicode,
	print_datum_stretch_key,
	print_datum_use_key,
	print_datum_aes_ccm,
	print_datum_tpmenc,
	print_datum_generic,
	print_datum_vmk,
	print_datum_external,
	print_datum_generic,
	print_datum_generic,
	print_datum_generic,
	print_datum_generic,
	print_datum_generic,
	print_datum_virtualization,
	print_datum_generic,
	print_datum_generic,
	print_datum_generic,
	print_datum_generic,
	print_datum_generic,
	print_datum_generic,
};


#ifdef _HAVE_RUBY
#include "dislocker/ruby.h"

void Init_datum(VALUE rb_cDislockerMetadata);

VALUE rb_cDislockerMetadataDatum_new(VALUE klass, VALUE datum);
#endif



#endif // DATUM_HEADER_H
