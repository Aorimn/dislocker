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


#include "common.h"
#include "metadata.h"
#include "extended_info.h"
#include "guid.h"
#include "ntfs/clock.h"
#include "ntfs/encoding.h"



/**
 * Cipher used within BitLocker
 */
enum cipher_types
{
	STRETCH_KEY   = 0x1000,
	AES_CCM_256_0 = 0x2000,
	AES_CCM_256_1 = 0x2001, 
	EXTERN_KEY    = 0x2002,
	VMK           = 0x2003,
	AES_CCM_256_2 = 0x2004,
	HASH_256      = 0x2005,
	
	AES_128_DIFFUSER    = 0x8000,
	AES_256_DIFFUSER    = 0x8001,
	AES_128_NO_DIFFUSER = 0x8002,
	AES_256_NO_DIFFUSER = 0x8003,
};
typedef uint16_t cipher_t;



/**
 * Here stand datum types stuff
 */
#define NB_DATUM_TYPES 20

enum datum_types
{
	/*  0 */ DATUM_ERASED = 0x0000,
	/*  1 */ DATUM_KEY,
	/*  2 */ DATUM_UNICODE,
	/*  3 */ DATUM_STRETCH_KEY,
	/*  4 */ DATUM_USE_KEY,
	/*  5 */ DATUM_AES_CCM,
	/*  6 */ DATUM_TPM_ENCODED,
	/*  7 */ DATUM_VALIDATION,
	/*  8 */ DATUM_VMK,
	/*  9 */ DATUM_EXTERNAL_KEY,
	/* 10 */ DATUM_UPDATE,
	/* 11 */ DATUM_ERROR,
	
	/* Below is only available on Windows Seven */
	/* 12 */ DATUM_ASYM_ENC,
	/* 13 */ DATUM_EXPORTED_KEY,
	/* 14 */ DATUM_PUBLIC_KEY,
	/* 15 */ DATUM_VIRTUALIZATION_INFO,
	/* 16 */ DATUM_SIMPLE_1,
	/* 17 */ DATUM_SIMPLE_2,
	/* 18 */ DATUM_CONCAT_HASH_KEY,
	/* 19 */ DATUM_SIMPLE_3
};
typedef uint16_t datum_t;





/**
 * This is the minimal header a datum has
 */
#pragma pack (1)
typedef struct _header_safe
{
	uint16_t datum_size;
	uint16_t type;
	datum_t  datum_type;
	uint16_t error_status;
} datum_header_safe_t;





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
typedef struct _datum_types_properties
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
} types_properties_t;

static const types_properties_t datum_types_prop[] =
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







/* Here are some specifics types (second field of the safe header) */
#define NB_TYPES 12

enum types
{
	TYPE_UNKNOWN1 = 0x0000,
	TYPE_UNKNOWN2,
	TYPE_VMK,
	TYPE_FVEK_INSIDE,
	TYPE_UNKNOWN3,
	TYPE_UNKNOWN4,
	TYPE_UNKNOWN5,
	TYPE_ENCTIME_INFORMATION,
	TYPE_UNKNOWN7,
	TYPE_UNKNOWN8,
	TYPE_UNKNOWN9,
	TYPE_UNKNOWN10,
	TYPE_FVEK_FveSynchronizeDatasetUpdate
};






/*
 * Here are prototypes of functions dealing with data
 */
char* cipherstr(cipher_t enc);
char* datumtypestr(datum_t datum_type);

int get_header_safe(void* data, datum_header_safe_t* header);

int get_payload_safe(void* data, void** payload, size_t* size_payload);

void print_one_datum(LEVELS level, void* datum);

void print_header(LEVELS level, datum_header_safe_t* header);

void print_datum_generic(LEVELS level, void* vdatum);
void print_datum_erased(LEVELS level, void* vdatum);
void print_datum_key(LEVELS level, void* vdatum);
void print_datum_unicode(LEVELS level, void* vdatum);
void print_datum_stretch_key(LEVELS level, void* vdatum);
void print_datum_use_key(LEVELS level, void* vdatum);
void print_datum_aes_ccm(LEVELS level, void* vdatum);
void print_datum_tpmenc(LEVELS level, void* vdatum);
void print_datum_vmk(LEVELS level, void* vdatum);
void print_datum_external(LEVELS level, void* vdatum);
void print_datum_virtualization(LEVELS level, void* vdatum);

void print_nonce(LEVELS level, uint8_t* nonce);
void print_mac(LEVELS level, uint8_t* mac);

int get_next_datum(bitlocker_dataset_t* dataset, int16_t type, int16_t datum_type, void* datum_begin, void** datum_result);

int get_nested_datum(void* datum, void** datum_nested);
int get_nested_datumtype(void* datum, datum_t datum_type, void** datum_nested);

int datum_type_must_be(void* datum, datum_t datum_type);

int has_clear_key(void* dataset, datum_vmk_t** vmk_datum);


typedef void(*print_datum_f)(LEVELS, void*);
static const print_datum_f print_datum_tab[NB_DATUM_TYPES] =
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
};



#endif // DATUM_HEADER_H
