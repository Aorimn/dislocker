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

#include <time.h>
#include <wchar.h>

#include "dislocker/metadata/datums.h"
#include "dislocker/metadata/vmk.h"
#include "dislocker/metadata/metadata.priv.h"



/** Datums value types into string */
static const char* value_type_str[] =
{
	"ERASED",
	"KEY",
	"UNICODE",
	"STRETCH KEY",
	"USE",
	"AES-CCM",
	"TPM_ENCODED",
	"VALIDATION",
	"VMK",
	"EXTERNAL KEY",
	"UPDATE",
	"ERROR",

	"ASYM ENC",
	"EXPORTED KEY",
	"PUBLIC KEY",
	"VIRTUALIZATION INFO",
	"SIMPLE 1",
	"SIMPLE 2",
	"CONCAT HASH KEY",
	"SIMPLE 3"
};



/** Datums entry types into string */
static const char* entry_type_str[] =
{
	"ENTRY TYPE UNKNOWN 1",
	"ENTRY TYPE UNKNOWN 2",
	"ENTRY TYPE VMK",
	"ENTRY TYPE FVEK (FveDatasetVmkGetFvek)",
	"ENTRY TYPE UNKNOWN",
	"ENTRY TYPE UNKNOWN",
	"ENTRY TYPE UNKNOWN",
	"ENTRY TYPE UNKNOWN",
	"ENTRY TYPE UNKNOWN",
	"ENTRY TYPE UNKNOWN",
	"ENTRY TYPE UNKNOWN",
	"ENTRY TYPE FVEK (TryObtainKey)" // also from "FveSynchronizeDatasetUpdate"
};






/**
 * Transform an algorithm code into its significant string
 * @warning This returned string has to be free()d
 *
 * @param enc The code of the algorithm
 * @return The string decoded
 */
char* cipherstr(cipher_t enc)
{
	size_t len;
	const char* value;
	char* data;

	switch (enc)
	{
		case 0:
			value = "NULL";
			break;
		case STRETCH_KEY :
			value = "STRETCH KEY";
			break;

		case AES_CCM_256_0 :
		case AES_CCM_256_1 :
		case AES_CCM_256_2 :
			value = "AES-CCM-256";
			break;

		case EXTERN_KEY :
			value = "EXTERN KEY";
			break;

		case VMK :
			value = "VMK";
			break;

		case HASH_256 :
			value = "VALIDATION HASH 256";
			break;

		case AES_128_DIFFUSER :
			value = "AES-128-DIFFUSER";
			break;

		case AES_256_DIFFUSER :
			value = "AES-256-DIFFUSER";
			break;

		case AES_128_NO_DIFFUSER :
			value = "AES-128-NODIFFUSER";
			break;

		case AES_256_NO_DIFFUSER :
			value = "AES-256-NODIFFUSER";
			break;

		case AES_XTS_128:
			value = "AES-XTS-128";
			break;

		case AES_XTS_256:
			value = "AES-XTS-256";
			break;

		default:
			value = "UNKNOWN CIPHER!";
			break;
	}

	len = strlen(value) + 1;
	data = (char*) dis_malloc(len * sizeof(char));
	memset(data, 0, len);
	memcpy(data, value, len);

	return data;
}


/**
 * Given a datum type code, it returns the corresponding signification in
 * string format
 * @warning This returned string has to be free()d
 *
 * @param value_type The datum's value type to transform
 * @return The decoded string or NULL if there's no signification (index out of
 * bound)
 */
char* datumvaluetypestr(dis_datums_value_type_t value_type)
{
	if(value_type >= NB_DATUMS_VALUE_TYPES)
		return NULL;


	size_t len = strlen(value_type_str[value_type]) + 1;
	char* data = (char*) dis_malloc(len * sizeof(char));
	memset(data, 0, len);
	memcpy(data, value_type_str[value_type], len);

	return data;
}


/**
 * Get a datum minimal header
 *
 * @param data Where to pick the datum header
 * @param header A datum header to retrieve
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_header_safe(void* data, datum_header_safe_t* header)
{
	// Check parameters
	if(!data)
		return FALSE;

	/* Too easy, boring */
	memcpy(header, data, sizeof(datum_header_safe_t));

	dis_printf(L_DEBUG, "Header safe: %#x, %#x, %#x, %#x\n", header->datum_size,
			header->entry_type, header->value_type, header->error_status);

	/* Now check if the header is good */
	if(header->datum_size < sizeof(datum_header_safe_t))
		return FALSE;

	return TRUE;
}


/**
 * Get the payload based on the datum's size and value type
 *
 * @param data The data to take the payload from
 * @param payload The extracted payload (need to be free()d if return is TRUE)
 * @param size_payload The malloc()ed payload size
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_payload_safe(void* data, void** payload, size_t* size_payload)
{
	// Check parameters
	if(!data)
		return FALSE;

	datum_header_safe_t header;
	uint16_t size_header = 0;

	if(!get_header_safe(data, &header))
		return FALSE;

	if(header.value_type > NB_DATUMS_VALUE_TYPES)
		return FALSE;

	size_header = datum_value_types_prop[header.value_type].size_header;

	if(header.datum_size <= size_header)
		return FALSE;

	*size_payload = (size_t)(header.datum_size - size_header);

	*payload = dis_malloc(*size_payload);

	memset(*payload, 0, *size_payload);
	memcpy(*payload, data + size_header, *size_payload);

	return TRUE;
}


/**
 * Print only one datum
 *
 * @param level The level to print the message
 * @param datum The datum to print
 */
void print_one_datum(DIS_LOGS level, void* datum)
{
	datum_header_safe_t* header = (datum_header_safe_t*) datum;
	print_header(level, header);

	dis_datums_value_type_t value_type = header->value_type;

	if (value_type < NB_DATUMS_VALUE_TYPES)
		print_datum_tab[value_type](level, datum);
}


/**
 * Print the header all data have
 *
 * @param level The level to print the message
 * @param header The header to print
 */
void print_header(DIS_LOGS level, datum_header_safe_t* header)
{
	dis_printf(level, "Total datum size: 0x%1$04hx (%1$hd) bytes\n", header->datum_size);

	dis_printf(level, "Datum entry type: %hu\n", header->entry_type);
	if(header->entry_type < NB_DATUMS_ENTRY_TYPES)
		dis_printf(level, "   `--> %s\n", entry_type_str[header->entry_type]);

	dis_printf(level, "Datum value type: %hu\n", header->value_type);

	if(header->value_type < NB_DATUMS_VALUE_TYPES)
	{
		dis_printf(level, "   `--> %s -- Total size header: %hu -- Nested datum: %s\n",
				value_type_str[header->value_type],
				datum_value_types_prop[header->value_type].size_header,
				(datum_value_types_prop[header->value_type].has_nested_datum ?
					"yes" : "no")
		);
	}

	dis_printf(level, "Status: %#x\n", header->error_status);
}


/**
 * Print information of a generic datum (one whose type is unknown)
 *
 * @param level The level to print the message
 * @param vdatum The datum to print
 */
void print_datum_generic(DIS_LOGS level, void* vdatum)
{
	datum_generic_type_t* datum = (datum_generic_type_t*) vdatum;

	dis_printf(level, "Generic datum:\n");
	hexdump(level, (void*)((char*)datum + sizeof(datum_generic_type_t)),
			datum->header.datum_size - sizeof(datum_generic_type_t));
}


/**
 * All the other specifics print functions
 *
 * @param level The level to print the message
 * @param datum The datum to print
 */
void print_datum_erased(DIS_LOGS level, void* vdatum)
{
	dis_printf(level, "This datum is of ERASED type and should thus be nullified");
	hexdump(level, vdatum, sizeof(datum_erased_t));
}

void print_datum_key(DIS_LOGS level, void* vdatum)
{
	datum_key_t* datum = (datum_key_t*) vdatum;
	char* cipher_str = cipherstr((cipher_t) datum->algo);

	dis_printf(level, "Unknown: \n");
	hexdump(level, (void*) &datum->padd, 2);
	dis_printf(level, "Algo: %s (%#hx)\n", cipher_str, datum->algo);
	dis_printf(level, "Key:\n");
	hexdump(
		level,
		(void*) ((char*) datum + sizeof(datum_key_t)),
		datum->header.datum_size - sizeof(datum_key_t)
	);

	dis_free(cipher_str);
}

void print_datum_unicode(DIS_LOGS level, void* vdatum)
{
	datum_unicode_t* datum = (datum_unicode_t*) vdatum;

	size_t utf16_length = (datum->header.datum_size - sizeof(datum_unicode_t));
	wchar_t* wchar_s = dis_malloc(
		((datum->header.datum_size - sizeof(datum_unicode_t)) / 2)
		* sizeof(wchar_t)
	);

	/*
	 * This datum's payload is an UTF-16 string finished by \0
	 * We convert it in wchar_t so we can print it
	 */
	utf16towchars(
		(uint16_t*) ((char*) datum + sizeof(datum_unicode_t)),
		utf16_length,
		wchar_s
	);
	dis_printf(level, "UTF-16 string: '%ls'\n", wchar_s);

	dis_free(wchar_s);
}

void print_datum_stretch_key(DIS_LOGS level, void* vdatum)
{
	datum_stretch_key_t* datum = (datum_stretch_key_t*) vdatum;

	dis_printf(level, "Unknown: \n");
	hexdump(level, (void*) &datum->padd, 2);
	dis_printf(level, "Algo: %#x\n", datum->algo);
	dis_printf(level, "Salt: \n");
	print_mac(level, datum->salt);

	/* This datum's payload seems to be another datum, so print it */
	dis_printf(level, "   ------ Nested datum ------\n");
	print_one_datum(level, (char*) datum + sizeof(datum_stretch_key_t));
	dis_printf(level, "   ---------------------------\n");
}

void print_datum_use_key(DIS_LOGS level, void* vdatum)
{
	datum_use_key_t* datum = (datum_use_key_t*) vdatum;

	dis_printf(level, "Algo: %#hx\n", datum->algo);
	dis_printf(level, "Unknown: \n");
	hexdump(level, (void*) &datum->padd, 2);

	/* This datum's payload seems to be another datum, so print it */
	dis_printf(level, "   ------ Nested datum ------\n");
	print_one_datum(level, (char*) datum + sizeof(datum_use_key_t));
	dis_printf(level, "   ---------------------------\n");
}

void print_datum_aes_ccm(DIS_LOGS level, void* vdatum)
{
	datum_aes_ccm_t* datum = (datum_aes_ccm_t*) vdatum;

	dis_printf(level, "Nonce: \n");
	print_nonce(level, datum->nonce);
	dis_printf(level, "MAC: \n");
	print_mac(level, datum->mac);
	dis_printf(level, "Payload:\n");
	hexdump(
		level,
		(void*) ((char*) datum + sizeof(datum_aes_ccm_t)),
		datum->header.datum_size - sizeof(datum_aes_ccm_t)
	);
}

void print_datum_tpmenc(DIS_LOGS level, void* vdatum)
{
	datum_tpm_enc_t* datum = (datum_tpm_enc_t*) vdatum;

	dis_printf(level, "Unknown: %#x\n", datum->unknown);
	dis_printf(level, "Payload:\n");
	hexdump(
		level,
		(void*) ((char*) datum + sizeof(datum_tpm_enc_t)),
		datum->header.datum_size - sizeof(datum_tpm_enc_t)
	);
}

void print_datum_vmk(DIS_LOGS level, void* vdatum)
{
	datum_vmk_t* datum = (datum_vmk_t*) vdatum;
	char extkey_id[37];
	int computed_size = 0;

	format_guid(datum->guid, extkey_id);

	dis_printf(level, "Recovery Key GUID: '%.39s'\n", extkey_id);
	dis_printf(level, "Nonce: \n");
	print_nonce(level, datum->nonce);

	computed_size = sizeof(datum_vmk_t);

	/* This datum's payload seems to be another datum, so print it */
	dis_printf(level, "   ------ Nested datum(s) ------\n");
	while(computed_size < datum->header.datum_size)
	{
		dis_printf(level, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
		print_one_datum(level, (char*) datum + computed_size);

		datum_header_safe_t header;
		memset(&header, 0, sizeof(datum_header_safe_t));

		get_header_safe((char*) datum + computed_size, &header);

		computed_size += header.datum_size;
		dis_printf(level, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	}
	dis_printf(level, "   ------------------------------\n");
}

void print_datum_external(DIS_LOGS level, void* vdatum)
{
	datum_external_t* datum = (datum_external_t*) vdatum;

	char extkey_id[37];
	time_t ts;
	char* date = NULL;
	int computed_size = 0;

	format_guid(datum->guid, extkey_id);
	ntfs2utc(datum->timestamp, &ts);
	date = strdup(asctime(gmtime(&ts)));
	chomp(date);

	dis_printf(level, "Recovery Key GUID: '%.39s'\n", extkey_id);
	dis_printf(
		level,
		"Epoch Timestamp: %u sec, being %s\n",
		(unsigned int) ts,
		date
	);

	computed_size = sizeof(datum_external_t);

	/* This datum's payload seems to be another datum, so print it */
	dis_printf(level, "   ------ Nested datum ------\n");
	while(computed_size < datum->header.datum_size)
	{
		dis_printf(level, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
		print_one_datum(level, (char*) datum + computed_size);

		datum_header_safe_t header;
		memset(&header, 0, sizeof(datum_header_safe_t));

		get_header_safe((char*) datum + computed_size, &header);

		computed_size += header.datum_size;
		dis_printf(level, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	}
	dis_printf(level, "   ---------------------------\n");

	free(date);
}

void print_datum_virtualization(DIS_LOGS level, void* vdatum)
{
	datum_virtualization_t* datum = (datum_virtualization_t*) vdatum;
	uint16_t value_type = datum->header.value_type;

	dis_printf(
		level,
		"NTFS boot sectors address:  %#" PRIx64 "\n",
		datum->ntfs_boot_sectors
	);
	dis_printf(
		level,
		"Number of backuped bytes: %1$#" PRIx64 " (%1$" PRIu64 ")\n",
		datum->nb_bytes
	);

	/* For Windows 8 encrypted volumes */
	size_t win7_size   = datum_value_types_prop[value_type].size_header;
	size_t actual_size = ((size_t)datum->header.datum_size) & 0xffff;
	if(actual_size > win7_size)
	{
		print_extended_info(level, &datum->xinfo);
	}
}



/**
 * Print a nonce
 *
 * @param level The level to print the message
 * @param nonce The nonce to print
 */
void print_nonce(DIS_LOGS level, uint8_t* nonce)
{
	int i = 0;
	char s[12*3 + 1] = {0,};

	for(i = 0; i < 12; ++i)
		snprintf(&s[i*3], 4, "%02hhx ", nonce[i]);

	dis_printf(level, "%s\n", s);
}


/**
 * Print MAC
 *
 * @param level The level to print the message
 * @param mac The MAC to print
 */
void print_mac(DIS_LOGS level, uint8_t* mac)
{
	int i = 0;
	char s[16*3 + 1] = {0,};

	for(i = 0; i < 16; ++i)
		snprintf(&s[i*3], 4, "%02hhx ", mac[i]);

	dis_printf(level, "%s\n", s);
}


/**
 * Get the next specified datum
 *
 * @param dis_metadata The metadata structure
 * @param entry_type The second uint16_t of any datum header struct
 * @param value_type The third uint16_t of any datum header struct
 * @param datum_begin The beginning of the search, begins after this given datum
 * @param datum_result The found datum
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_next_datum(
	dis_metadata_t dis_meta,
	dis_datums_entry_type_t entry_type,
	dis_datums_value_type_t value_type,
	void* datum_begin,
	void** datum_result)
{
	// Check parameters
	if(!dis_meta)
		return FALSE;

	dis_printf(L_DEBUG, "Entering get_next_datum...\n");

	bitlocker_dataset_t* dataset = dis_meta->dataset;
	void* datum = NULL;
	void* limit = (char*)dataset + dataset->size;
	datum_header_safe_t header;

	*datum_result = NULL;
	memset(&header, 0, sizeof(datum_header_safe_t));
	if(datum_begin)
		datum = datum_begin + *(uint16_t*)datum_begin;
	else
		datum = (char*)dataset + dataset->header_size;

	while(1)
	{
		if(datum + 8 >= limit)
		{
			dis_printf(L_DEBUG, "Hit limit, search failed.\n");
			break;
		}

		if(!get_header_safe(datum, &header))
			break;

		if(value_type == UINT16_MAX && entry_type == UINT16_MAX)
		{
			/*
			 * If the datum types are not in range, assume the caller want each
			 * datum
			 */
			*datum_result = datum;
			break;
		}
		else if((entry_type == header.entry_type || entry_type == UINT16_MAX) &&
		        (value_type == header.value_type || value_type == UINT16_MAX))
		{
			/*
			 * If the entry type and the value type searched match,
			 * then return this datum
			 */
			*datum_result = datum;
			break;
		}

		datum += header.datum_size;

		memset(&header, 0, sizeof(datum_header_safe_t));
	}

	dis_printf(L_DEBUG, "Going out of get_next_datum\n");

	if(!*datum_result)
		return FALSE;

	return TRUE;
}


/**
 * Retrieve a datum nested into another one
 *
 * @param datum Where to find a nested datum
 * @param datum_nested The datum resulted
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_nested_datum(void* datum, void** datum_nested)
{
	// Check parameters
	if(!datum)
		return FALSE;

	datum_header_safe_t header;

	if(!get_header_safe(datum, &header))
		return FALSE;

	if(header.value_type > NB_DATUMS_VALUE_TYPES)
		return FALSE;

	if(!datum_value_types_prop[header.value_type].has_nested_datum)
		return FALSE;

	uint16_t size = datum_value_types_prop[header.value_type].size_header;
	*datum_nested = (char*)datum + size;

	return TRUE;
}


/**
 * Retrieve a datum nested into another one with a specific value type
 *
 * @param datum Where to find a nested datum
 * @param value_type The datum of the searched datum
 * @param datum_nested The datum resulted
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_nested_datumvaluetype(void* datum, dis_datums_value_type_t value_type, void** datum_nested)
{
	// Check parameters
	if(!datum)
		return FALSE;

	/* Get the first nested datum */
	if(!get_nested_datum(datum, datum_nested))
		return FALSE;

	datum_header_safe_t header;
	datum_header_safe_t nested_header;

	if(!get_header_safe(datum, &header))
		return FALSE;

	if(!get_header_safe(*datum_nested, &nested_header))
		return FALSE;

	/* While we don't have the type we're looking for */
	while(nested_header.value_type != value_type)
	{
		/* Just go to the next datum */
		*datum_nested += nested_header.datum_size;

		/* If we're not into the datum anymore */
		if((char*)datum + header.datum_size <= (char*)*datum_nested)
			return FALSE;

		if(!get_header_safe(*datum_nested, &nested_header))
			return FALSE;

	}

	return TRUE;
}


/**
 * Safely check of the datum's value type
 *
 * @param datum The datum to validate
 * @param value_type The datum's value type to find
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int datum_value_type_must_be(void* datum, dis_datums_value_type_t value_type)
{
	// Check parameters
	if(!datum)
		return FALSE;

	datum_header_safe_t header;

	if(!get_header_safe(datum, &header))
		return FALSE;

	if(header.value_type == value_type)
		return TRUE;
	else
		return FALSE;
}


/**
 * Check if a clear key is stored in data
 *
 * @param dataset The metadata's dataset
 * @param vmk_datum The VMK datum of the clear key if found
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int dis_metadata_has_clear_key(dis_metadata_t dis_meta, void** vmk_datum)
{
	if(!dis_meta)
		return FALSE;

	*vmk_datum = NULL;

	dis_printf(L_DEBUG, "Entering has_clear_key. Returning result of get_vmk_datum_from_range with range between 0x00 and 0xff\n");

	return get_vmk_datum_from_range(dis_meta, 0x00, 0xff, vmk_datum, NULL);
}



#ifdef _HAVE_RUBY
#include "dislocker/dislocker.priv.h"

struct _rb_dis_datum {
	/* The actual datum's data */
	datum_generic_type_t* datum;

	/* If the datum was malloc()-ed, then it needs to be free()-d */
	char need_free;
};
typedef struct _rb_dis_datum* rb_dis_datum_t;

/* Declare this function for recursive to_s datums */
static VALUE rb_cDislockerMetadataDatum_to_s(VALUE self);


static VALUE rb_cDislockerMetadataDatum_get_datum_size(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	return INT2NUM(rb_datum->datum->header.datum_size);
}

static VALUE rb_cDislockerMetadataDatum_get_entry_type(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	return INT2NUM(rb_datum->datum->header.entry_type);
}

static VALUE rb_cDislockerMetadataDatum_get_value_type(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	return INT2NUM(rb_datum->datum->header.value_type);
}

static VALUE rb_cDislockerMetadataDatum_get_error_status(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	return INT2NUM(rb_datum->datum->header.error_status);
}

static VALUE rb_cDislockerMetadataDatum_get_payload(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	void* payload = NULL;
	size_t size = 0;
	extern VALUE dis_rb_classes[DIS_RB_CLASS_MAX];

	if(get_payload_safe(rb_datum->datum, &payload, &size))
	{
		if(size > LONG_MAX)
		{
			rb_raise(
				rb_eRuntimeError,
				"Wtf with this datum's payload size (%" F_SIZE_T ")?",
				size
			);
		}

		VALUE new_rb_datum = rb_cDislockerMetadataDatum_new(
			dis_rb_classes[DIS_RB_CLASS_DATUM],
			rb_str_new(payload, (long int) size)
		);

		return new_rb_datum;
	}

	return Qnil;
}

static VALUE rb_format_mac(uint8_t* mac)
{
	VALUE rb_str = rb_str_new("", 0);
	int i = 0;
	char s[16*3 + 1] = {0,};

	for(i = 0; i < 16; ++i)
		snprintf(&s[i*3], 4, "%02hhx ", mac[i]);

	rb_str_catf(rb_str, "%s\n", s);

	return rb_str;
}

static VALUE rb_format_nonce(uint8_t* nonce)
{
	VALUE rb_str = rb_str_new("", 0);
	int i = 0;
	char s[12*3 + 1] = {0,};

	for(i = 0; i < 12; ++i)
		snprintf(&s[i*3], 4, "%02hhx ", nonce[i]);

	rb_str_catf(rb_str, "%s\n", s);

	return rb_str;
}

static VALUE rb_cDislockerMetadataDatumHeader_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_generic_type_t* gt = rb_datum->datum;
	char* entry_type = "UNKNOWN";
	char* value_type = "UNKNOWN";

	VALUE rb_str = rb_str_new("", 0);

	if(gt == NULL)
		return rb_str;

	if(gt->header.entry_type < NB_DATUMS_ENTRY_TYPES)
		entry_type = (char*) entry_type_str[gt->header.entry_type];

	if(gt->header.value_type < NB_DATUMS_VALUE_TYPES)
		value_type = (char*) value_type_str[gt->header.value_type];


	rb_str_catf(
		rb_str,
		"Total size: 0x%04hx (%hd) bytes\n",
		gt->header.datum_size,
		gt->header.datum_size
	);

	rb_str_catf( rb_str,
		"Entry type: %s (%hu)\n",
		entry_type,
		gt->header.entry_type
	);

	rb_str_catf(
		rb_str,
		"Value type: %s (%hu)\n",
		value_type,
		gt->header.value_type
	);

	rb_str_catf(
		rb_str,
		"Status    : %#x\n",
		gt->header.error_status
	);

	return rb_str;
}


VALUE rb_datum_generic_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_generic_type_t* datum = rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	rb_str_cat2(rb_str, "Generic datum: ");

	rb_str_concat(rb_str, rb_hexdump(
		(uint8_t*) datum + sizeof(datum_generic_type_t),
		datum->header.datum_size - sizeof(datum_generic_type_t)
	));

	return rb_str;
}

VALUE rb_datum_erased_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_generic_type_t* datum = rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	rb_str_cat2(rb_str, "This datum is of ERASED type and should thus be nullified");

	return rb_str;
}

VALUE rb_datum_key_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_key_t* datum = (datum_key_t*) rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	char* cipher_str = cipherstr((cipher_t) datum->algo);

	rb_str_catf(rb_str, "Unknown: 0x%04hx\n", datum->padd);
	rb_str_catf(rb_str, "Algo: %s (%#hx)\n", cipher_str, datum->algo);
	rb_str_cat2(rb_str, "Key:\n");
	rb_str_concat(rb_str, rb_hexdump(
		(uint8_t*) datum + sizeof(datum_key_t),
		datum->header.datum_size - sizeof(datum_key_t)
	));

	dis_free(cipher_str);

	return rb_str;
}

VALUE rb_datum_unicode_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_unicode_t* datum = (datum_unicode_t*) rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	size_t utf16_length = (datum->header.datum_size - sizeof(datum_unicode_t));
	wchar_t* wchar_s = dis_malloc(
		((datum->header.datum_size - sizeof(datum_unicode_t)) / 2)
		* sizeof(wchar_t)
	);

	/*
	 * This datum's payload is an UTF-16 string finished by \0
	 * We convert it in wchar_t so we can print it
	 */
	utf16towchars(
		(uint16_t*)((char*) datum + sizeof(datum_unicode_t)),
		utf16_length,
		wchar_s
	);
	rb_str_catf(rb_str, "UTF-16 string: '%ls'\n", wchar_s);

	dis_free(wchar_s);

	return rb_str;
}

VALUE rb_datum_stretch_key_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_stretch_key_t* datum = (datum_stretch_key_t*) rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	rb_str_catf(rb_str, "Unknown: 0x%04hx\n", datum->padd);
	rb_str_catf(rb_str, "Algo: %#x\n", datum->algo);
	rb_str_cat2(rb_str, "Salt: \n");
	rb_str_concat(rb_str, rb_format_mac(datum->salt));

	/* This datum's payload seems to be another datum, so print it */
	rb_str_cat2(rb_str, "   ------ Nested datum ------\n");

	rb_datum->datum = (datum_generic_type_t*)
	                  datum + sizeof(datum_stretch_key_t);
	rb_str_concat(rb_str, rb_cDislockerMetadataDatum_to_s(self));

	rb_str_cat2(rb_str, "   ---------------------------\n");

	rb_datum->datum = (datum_generic_type_t*) datum;

	return rb_str;
}

VALUE rb_datum_use_key_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_use_key_t* datum = (datum_use_key_t*) rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	rb_str_catf(rb_str, "Algo: %#hx\n", datum->algo);
	rb_str_catf(rb_str, "Unknown: 0x%04hx\n", datum->padd);

	/* This datum's payload seems to be another datum, so print it */
	rb_str_cat2(rb_str, "   ------ Nested datum ------\n");
	rb_datum->datum = (datum_generic_type_t*) datum + sizeof(datum_use_key_t);
	rb_str_concat(rb_str, rb_cDislockerMetadataDatum_to_s(self));
	rb_str_cat2(rb_str, "   ---------------------------\n");

	rb_datum->datum = (datum_generic_type_t*) datum;

	return rb_str;
}

VALUE rb_datum_aes_ccm_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_aes_ccm_t* datum = (datum_aes_ccm_t*) rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	rb_str_cat2(rb_str, "Nonce:\n");
	rb_str_concat(rb_str, rb_format_nonce(datum->nonce));
	rb_str_cat2(rb_str, "MAC:\n");
	rb_str_concat(rb_str, rb_format_mac(datum->mac));
	rb_str_cat2(rb_str, "Payload:\n");
	rb_str_concat(rb_str, rb_hexdump(
		(uint8_t*) ((char*) datum + sizeof(datum_aes_ccm_t)),
		datum->header.datum_size - sizeof(datum_aes_ccm_t)
	));

	return rb_str;
}

VALUE rb_datum_tpmenc_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_tpm_enc_t* datum = (datum_tpm_enc_t*) rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	rb_str_catf(rb_str, "Unknown: %#x\n", datum->unknown);
	rb_str_cat2(rb_str, "Payload:\n");
	rb_str_concat(rb_str, rb_hexdump(
		(uint8_t*) ((char*) datum + sizeof(datum_tpm_enc_t)),
		datum->header.datum_size - sizeof(datum_tpm_enc_t)
	));

	return rb_str;
}

VALUE rb_datum_vmk_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_vmk_t* datum = (datum_vmk_t*) rb_datum->datum;
	char extkey_id[37];
	int computed_size = 0;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	format_guid(datum->guid, extkey_id);

	rb_str_catf(rb_str, "Recovery Key GUID: '%.39s'\n", extkey_id);
	rb_str_cat2(rb_str, "Nonce: \n");
	rb_str_concat(rb_str, rb_format_nonce(datum->nonce));

	computed_size = sizeof(datum_vmk_t);

	/* This datum's payload seems to be another datum, so print it */
	while(computed_size < datum->header.datum_size)
	{
		rb_str_cat2(rb_str, "   ------ Nested datum(s) ------\n");
		rb_datum->datum = (datum_generic_type_t*) datum + computed_size;
		rb_str_concat(rb_str, rb_cDislockerMetadataDatum_to_s(self));

		datum_header_safe_t header;
		memset(&header, 0, sizeof(datum_header_safe_t));

		get_header_safe((char*) datum + computed_size, &header);

		computed_size += header.datum_size;
		rb_str_cat2(rb_str, "   ------------------------------\n");
	}

	rb_datum->datum = (datum_generic_type_t*) datum;

	return rb_str;
}

VALUE rb_datum_external_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_external_t* datum = (datum_external_t*) rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	char extkey_id[37];
	time_t ts;
	char* date = NULL;
	int computed_size = 0;

	format_guid(datum->guid, extkey_id);
	ntfs2utc(datum->timestamp, &ts);
	date = strdup(asctime(gmtime(&ts)));
	chomp(date);

	rb_str_catf(rb_str, "Recovery Key GUID: '%.39s'\n", extkey_id);
	rb_str_catf(
		rb_str,
		"Epoch Timestamp: %u sec, being %s\n",
		(unsigned int) ts,
		date
	);

	computed_size = sizeof(datum_external_t);

	/* This datum's payload seems to be another datum, so print it */
	while(computed_size < datum->header.datum_size)
	{
		rb_str_cat2(rb_str, "   ------ Nested datum ------\n");
		rb_datum->datum = (datum_generic_type_t*) datum + computed_size;
		rb_str_concat(rb_str, rb_cDislockerMetadataDatum_to_s(self));

		datum_header_safe_t header;
		memset(&header, 0, sizeof(datum_header_safe_t));

		get_header_safe((char*) datum + computed_size, &header);

		computed_size += header.datum_size;
		rb_str_cat2(rb_str, "   ---------------------------\n");
	}

	free(date);

	rb_datum->datum = (datum_generic_type_t*) datum;

	return rb_str;
}

VALUE rb_datum_virtualization_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_virtualization_t* datum = (datum_virtualization_t*) rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(datum == NULL)
		return rb_str;

	uint16_t value_type = datum->header.value_type;

	rb_str_catf(
		rb_str,
		"NTFS boot sectors address:  %#" PRIx64 "\n",
		datum->ntfs_boot_sectors
	);
	rb_str_catf(
		rb_str,
		"Number of backuped bytes: %1$#" PRIx64 " (%1$" PRIu64 ")\n",
		datum->nb_bytes
	);

	/* For Windows 8 encrypted volumes */
	size_t win7_size   = datum_value_types_prop[value_type].size_header;
	size_t actual_size = ((size_t)datum->header.datum_size) & 0xffff;
	if(actual_size > win7_size)
	{
		rb_str_concat(
			rb_str,
			rb_datum_virtualization_extinfo_to_s(&datum->xinfo)
		);
	}

	return rb_str;
}

typedef VALUE (*rb_datum_to_s_f)(VALUE self);
static const rb_datum_to_s_f rb_datum_to_s_tab[NB_DATUMS_VALUE_TYPES] =
{
	rb_datum_erased_to_s,
	rb_datum_key_to_s,
	rb_datum_unicode_to_s,
	rb_datum_stretch_key_to_s,
	rb_datum_use_key_to_s,
	rb_datum_aes_ccm_to_s,
	rb_datum_tpmenc_to_s,
	rb_datum_generic_to_s,
	rb_datum_vmk_to_s,
	rb_datum_external_to_s,
	rb_datum_generic_to_s,
	rb_datum_generic_to_s,
	rb_datum_generic_to_s,
	rb_datum_generic_to_s,
	rb_datum_generic_to_s,
	rb_datum_virtualization_to_s,
	rb_datum_generic_to_s,
	rb_datum_generic_to_s,
	rb_datum_generic_to_s,
	rb_datum_generic_to_s,
};

VALUE rb_cDislockerMetadataDatumPayload_to_s(VALUE self)
{
	rb_dis_datum_t rb_datum = DATA_PTR(self);
	datum_generic_type_t* gt = rb_datum->datum;

	VALUE rb_str = rb_str_new("", 0);

	if(gt == NULL)
		return rb_str;

	if(gt->header.value_type < NB_DATUMS_VALUE_TYPES)
		return rb_datum_to_s_tab[gt->header.value_type](self);

	return rb_str;
}

static VALUE rb_cDislockerMetadataDatum_to_s(VALUE self)
{
	VALUE rb_str = rb_cDislockerMetadataDatumHeader_to_s(self);

	rb_str_concat(rb_str, rb_cDislockerMetadataDatumPayload_to_s(self));

	return rb_str;
}


static void rb_cDislockerMetadataDatum_free(rb_dis_datum_t rb_datum)
{
	if(rb_datum)
	{
		if(rb_datum->need_free)
			dis_free(rb_datum->datum);
		dis_free(rb_datum);
	}
}

static VALUE rb_cDislockerMetadataDatum_alloc(VALUE klass)
{
	rb_dis_datum_t datum = NULL;

	return Data_Wrap_Struct(
		klass,
		NULL,
		rb_cDislockerMetadataDatum_free,
		datum
	);
}

static VALUE rb_cDislockerMetadataDatum_init(VALUE self, VALUE datum)
{
	rb_dis_datum_t rb_datum = dis_malloc(sizeof(struct _rb_dis_datum));
	if(rb_datum == NULL)
		rb_raise(rb_eRuntimeError, "Cannot allocate more memory");

	memset(rb_datum, 0, sizeof(struct _rb_dis_datum));

	DATA_PTR(self) = rb_datum;

	Check_Type(datum, T_STRING);
	rb_datum->datum = (datum_generic_type_t*) StringValuePtr(datum);

	return Qnil;
}

VALUE rb_cDislockerMetadataDatum_new(VALUE klass, VALUE datum)
{
	VALUE rb_datum = rb_cDislockerMetadataDatum_alloc(klass);
	rb_cDislockerMetadataDatum_init(rb_datum, datum);

	return rb_datum;
}

void Init_datum(VALUE rb_cDislockerMetadata)
{
	VALUE rb_cDislockerMetadataDatum = rb_define_class_under(
		rb_cDislockerMetadata,
		"Datum",
		rb_cObject
	);
	extern VALUE dis_rb_classes[DIS_RB_CLASS_MAX];
	dis_rb_classes[DIS_RB_CLASS_DATUM] = rb_cDislockerMetadataDatum;

	rb_define_alloc_func(
		rb_cDislockerMetadataDatum,
		rb_cDislockerMetadataDatum_alloc
	);
	rb_define_method(
		rb_cDislockerMetadataDatum,
		"initialize",
		rb_cDislockerMetadataDatum_init,
		1
	);

	rb_define_method(
		rb_cDislockerMetadataDatum,
		"size",
		rb_cDislockerMetadataDatum_get_datum_size,
		0
	);
	rb_define_method(
		rb_cDislockerMetadataDatum,
		"entry_type",
		rb_cDislockerMetadataDatum_get_entry_type,
		0
	);
	rb_define_method(
		rb_cDislockerMetadataDatum,
		"value_type",
		rb_cDislockerMetadataDatum_get_value_type,
		0
	);
	rb_define_method(
		rb_cDislockerMetadataDatum,
		"error_status",
		rb_cDislockerMetadataDatum_get_error_status,
		0
	);
	rb_define_method(
		rb_cDislockerMetadataDatum,
		"payload",
		rb_cDislockerMetadataDatum_get_payload,
		0
	);
	rb_define_method(
		rb_cDislockerMetadataDatum,
		"to_s",
		rb_cDislockerMetadataDatum_to_s,
		0
	);
}
#endif /* _HAVE_RUBY */
