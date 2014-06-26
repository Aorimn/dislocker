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

#include "datums.h"
#include "vmk.h"



/** Datum types into string */
static const char* datum_types_str[] =
{
	"DATUM_ERASED",
	"DATUM_KEY",
	"DATUM_UNICODE",
	"DATUM_STRETCH_KEY",
	"DATUM_USE",
	"DATUM_AES_CCM",
	"DATUM_TPM_ENCODED",
	"DATUM_VALIDATION",
	"DATUM_VMK",
	"DATUM_EXTERNAL_KEY",
	"DATUM_UPDATE",
	"DATUM_ERROR",
	
	"DATUM_ASYM_ENC",
	"DATUM_EXPORTED_KEY",
	"DATUM_PUBLIC_KEY",
	"DATUM_VIRTUALIZATION_INFO",
	"DATUM_SIMPLE_1",
	"DATUM_SIMPLE_2",
	"DATUM_CONCAT_HASH_KEY",
	"DATUM_SIMPLE_3"
};



/** Types into string */
static const char* types_str[] =
{
	"TYPE_UNKNOWN_1",
	"TYPE_UNKNOWN_2",
	"TYPE_VMK",
	"TYPE_FVEK_FveDatasetVmkGetFvek",
	"TYPE_UNKNOWN_3",
	"TYPE_UNKNOWN_4",
	"TYPE_UNKNOWN_5",
	"TYPE_UNKNOWN_6",
	"TYPE_UNKNOWN_7",
	"TYPE_UNKNOWN_8",
	"TYPE_UNKNOWN_9",
	"TYPE_FVEK_TryObtainKey" // also "TYPE_FVEK_FveSynchronizeDatasetUpdate" if we want
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
		case STRETCH_KEY :
			value = "STRETCH_KEY";
			break;
		
		case AES_CCM_256_0 :
		case AES_CCM_256_1 :
		case AES_CCM_256_2 :
			value = "AES_CCM_256";
			break;
		
		case EXTERN_KEY :
			value = "EXTERN_KEY";
			break;
		
		case VMK :
			value = "VMK";
			break;
		
		case HASH_256 :
			value = "VALIDATION_HASH_256";
			break;
		
		case AES_128_DIFFUSER :
			value = "AES_128_DIFFUSER";
			break;
		
		case AES_256_DIFFUSER :
			value = "AES_256_DIFFUSER";
			break;
		
		case AES_128_NO_DIFFUSER :
			value = "AES_128_NO_DIFFUSER";
			break;
		
		case AES_256_NO_DIFFUSER :
			value = "AES_256_NO_DIFFUSER";
			break;
		default:
			value = "UNKNOWN CIPHER!";
			break;
	}
	
	len = strlen(value) + 1;
	data = (char*) xmalloc(len * sizeof(char));
	memset(data, 0, len);
	memcpy(data, value, len);
	
	return data; 
}


/**
 * Given a datum type code, it returns the corresponding signification in
 * string format
 * @warning This returned string has to be free()d
 * 
 * @param datum_type The datum type to tranform
 * @return The decoded string or NULL if there's no signification (index out of
 * bound)
 */
char* datumtypestr(datum_t datum_type)
{
	if(datum_type >= NB_DATUM_TYPES)
		return NULL;
	
	
	size_t len = strlen(datum_types_str[datum_type]) + 1;
	char* data = (char*) xmalloc(len * sizeof(char));
	memset(data, 0, len);
	memcpy(data, datum_types_str[datum_type], len);
	
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
	
	xprintf(L_DEBUG, "Header safe: %#x, %#x, %#x, %#x\n", header->datum_size,
			header->type, header->datum_type, header->error_status);
	
	/* Now check if the header is good */
	if(header->datum_size < sizeof(datum_header_safe_t) || header->datum_type > NB_DATUM_TYPES)
		return FALSE;
	
	return TRUE;
}


/**
 * Get the payload based on the datum size and type
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
	
	size_header = datum_types_prop[header.datum_type].size_header;
	
	if(header.datum_size <= size_header)
		return FALSE;
	
	*size_payload = (size_t)(header.datum_size - size_header);
	
	*payload = xmalloc(*size_payload);
	
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
void print_one_datum(LEVELS level, void* datum)
{
	datum_header_safe_t* header = (datum_header_safe_t*) datum;
	print_header(level, header);
	
	uint16_t datum_type = header->datum_type;
	
	print_datum_tab[datum_type](level, datum);
}


/**
 * Print the header all data have
 * 
 * @param level The level to print the message
 * @param header The header to print
 */
void print_header(LEVELS level, datum_header_safe_t* header)
{
	xprintf(level, "Total datum size: 0x%1$04hx (%1$hd) bytes\n", header->datum_size);
	
	xprintf(level, "Type: %hu\n", header->type);
	if(header->type < NB_TYPES)
		xprintf(level, "   `--> %s\n", types_str[header->type]);
	
	xprintf(level, "Datum type: %hu\n", header->datum_type);
	
	if(header->datum_type < NB_DATUM_TYPES)
	{
		xprintf(level, "   `--> %s -- Total size header: %hu -- Nested datum: %s\n",
				datum_types_str[header->datum_type],
				datum_types_prop[header->datum_type].size_header,
				(datum_types_prop[header->datum_type].has_nested_datum ?
					"yes" : "no")
		);
	}
	
	xprintf(level, "Status: %#x\n", header->error_status);
}


/**
 * Print information of a generic datum (one whose type is unknown)
 * 
 * @param level The level to print the message
 * @param vdatum The datum to print
 */
void print_datum_generic(LEVELS level, void* vdatum)
{
	datum_generic_type_t* datum = (datum_generic_type_t*) vdatum;
	
	xprintf(level, "Generic datum:\n");
	hexdump(level, (void*)((char*)datum + sizeof(datum_generic_type_t)),
			datum->header.datum_size - sizeof(datum_generic_type_t));
}


/**
 * All the other specifics print functions
 * 
 * @param level The level to print the message
 * @param datum The datum to print
 */
void print_datum_erased(LEVELS level, void* vdatum)
{
	xprintf(level, "This datum is of ERASED type and should thus be nullified");
	hexdump(level, vdatum, sizeof(datum_erased_t));
}

void print_datum_key(LEVELS level, void* vdatum)
{
	datum_key_t* datum = (datum_key_t*) vdatum;
	char* cipher_str_type = cipherstr((cipher_t)datum->algo);
	
	xprintf(level, "Unkown: \n");
	hexdump(level, (void*)&datum->padd, 2);
	xprintf(level, "Algo: %s (%#x)\n", cipher_str_type, datum->algo);
	xprintf(level, "Key:\n");
	hexdump(level, (void*)((char*)datum + sizeof(datum_key_t)), datum->header.datum_size - sizeof(datum_key_t));
	
	xfree(cipher_str_type);
}

void print_datum_unicode(LEVELS level, void* vdatum)
{
	datum_unicode_t* datum = (datum_unicode_t*) vdatum;
	
	size_t utf16_length = (datum->header.datum_size - sizeof(datum_unicode_t));
	wchar_t* wchar_s = xmalloc(((datum->header.datum_size - sizeof(datum_unicode_t)) / 2) * sizeof(wchar_t));
	
	/*
	 * This datum's payload is an UTF-16 string finished by \0
	 * We convert it in wchar_t so we can print it
	 */
	utf16towchars((uint16_t*)((char*)datum + sizeof(datum_unicode_t)), utf16_length, wchar_s);
	xprintf(level, "UTF-16 string: '%ls'\n", wchar_s);
	
	xfree(wchar_s);
}

void print_datum_stretch_key(LEVELS level, void* vdatum)
{
	datum_stretch_key_t* datum = (datum_stretch_key_t*) vdatum;
	
	xprintf(level, "Unkown: \n");
	hexdump(level, (void*)&datum->padd, 2);
	xprintf(level, "Algo: %#x\n", datum->algo);
	xprintf(level, "Salt: \n");
	print_mac(level, datum->salt);
	
	/* This datum's payload seems to be another datum, so print it */
	xprintf(level, "   ------ Nested datum ------\n");
	print_one_datum(level, (char*)datum + sizeof(datum_stretch_key_t));
	xprintf(level, "   ---------------------------\n");
}

void print_datum_use_key(LEVELS level, void* vdatum)
{
	datum_use_key_t* datum = (datum_use_key_t*) vdatum;
	
	xprintf(level, "Algo: %#hx\n", datum->algo);
	xprintf(level, "Unkown: \n");
	hexdump(level, (void*)&datum->padd, 2);
	
	/* This datum's payload seems to be another datum, so print it */
	xprintf(level, "   ------ Nested datum ------\n");
	print_one_datum(level, (char*)datum + sizeof(datum_use_key_t));
	xprintf(level, "   ---------------------------\n");
}

void print_datum_aes_ccm(LEVELS level, void* vdatum)
{
	datum_aes_ccm_t* datum = (datum_aes_ccm_t*) vdatum;
	
	xprintf(level, "Nonce: \n");
	print_nonce(level, datum->nonce);
	xprintf(level, "MAC: \n");
	print_mac(level, datum->mac);
	xprintf(level, "Payload:\n");
	hexdump(level, (void*)((char*)datum + sizeof(datum_aes_ccm_t)),
			datum->header.datum_size - sizeof(datum_aes_ccm_t));
}

void print_datum_tpmenc(LEVELS level, void* vdatum)
{
	datum_tpm_enc_t* datum = (datum_tpm_enc_t*) vdatum;
	
	xprintf(level, "Unknown: %#x\n", datum->unknown);
	xprintf(level, "Payload:\n");
	hexdump(level, (void*)((char*)datum + sizeof(datum_tpm_enc_t)),
			datum->header.datum_size - sizeof(datum_tpm_enc_t));
}

void print_datum_vmk(LEVELS level, void* vdatum)
{
	datum_vmk_t* datum = (datum_vmk_t*) vdatum;
	char extkey_id[37];
	int computed_size = 0;
	
	format_guid(datum->guid, extkey_id);
	
	xprintf(level, "Recovery Key GUID: '%.39s'\n", extkey_id);
	xprintf(level, "Nonce: \n");
	print_nonce(level, datum->nonce);
	
	computed_size = sizeof(datum_vmk_t);
	
	/* This datum's payload seems to be another datum, so print it */
	xprintf(level, "   ------ Nested datum(s) ------\n");
	while(computed_size < datum->header.datum_size)
	{
		xprintf(level, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
		print_one_datum(level, (char*)datum + computed_size);
		
		datum_header_safe_t header;
		memset(&header, 0, sizeof(datum_header_safe_t));
		
		get_header_safe((char*)datum + computed_size, &header);
		
		computed_size += header.datum_size;
		xprintf(level, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	}
	xprintf(level, "   ------------------------------\n");
}

void print_datum_external(LEVELS level, void* vdatum)
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
	
	xprintf(level, "Recovery Key GUID: '%.39s'\n", extkey_id);
	xprintf(level, "Epoch Timestamp: %u sec, soit %s\n", (unsigned int)ts, date);
	
	computed_size = sizeof(datum_external_t);
	
	/* This datum's payload seems to be another datum, so print it */
	xprintf(level, "   ------ Nested datum ------\n");
	while(computed_size < datum->header.datum_size)
	{
		xprintf(level, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
		print_one_datum(level, (char*)datum + computed_size);
		
		datum_header_safe_t header;
		memset(&header, 0, sizeof(datum_header_safe_t));
		
		get_header_safe((char*)datum + computed_size, &header);
		
		computed_size += header.datum_size;
		xprintf(level, "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
	}
	xprintf(level, "   ---------------------------\n");
	
	free(date);
}

void print_datum_virtualization(LEVELS level, void* vdatum)
{
	datum_virtualization_t* datum = (datum_virtualization_t*) vdatum;
	
	xprintf(level, "NTFS boot sectors address:  %#llx\n", datum->ntfs_boot_sectors);
	xprintf(level, "Number of backuped bytes: %1$#llx (%1$llu)\n", datum->nb_bytes);
	
	/* For Windows 8 metadata */
	size_t win7_size   = datum_types_prop[datum->header.datum_type].size_header;
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
void print_nonce(LEVELS level, uint8_t* nonce)
{
	int i = 0;
	char s[12*3 + 1] = {0,};
	
	for(i = 0; i < 12; ++i)
		snprintf(&s[i*3], 4, "%02hhx ", nonce[i]);
	
	xprintf(level, "%s\n", s);
}


/**
 * Print MAC
 * 
 * @param level The level to print the message
 * @param mac The MAC to print
 */
void print_mac(LEVELS level, uint8_t* mac)
{
	int i = 0;
	char s[16*3 + 1] = {0,};
	
	for(i = 0; i < 16; ++i)
		snprintf(&s[i*3], 4, "%02hhx ", mac[i]);
	
	xprintf(level, "%s\n", s);
}


/**
 * Get the next specified datum
 * 
 * @param dataset The metadata dataset
 * @param type The second uint16_t of any datum header struct
 * @param datum_type The third uint16_t of any datum header struct
 * @param datum_begin The beginning of the search
 * @param datum_result The found datum
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_next_datum(bitlocker_dataset_t* dataset, int16_t type, int16_t datum_type, void* datum_begin, void** datum_result)
{
	// Check parameters
	if(!dataset || datum_type > NB_DATUM_TYPES)
		return FALSE;
	
	
	xprintf(L_DEBUG, "Entering get_next_datum...\n");
	
	void* datum = NULL;
	datum_header_safe_t header;
	
	*datum_result = NULL;
	memset(&header, 0, sizeof(datum_header_safe_t));
	if(datum_begin)
		datum = datum_begin + *(uint16_t*)datum_begin;
	else
		datum = (char*)dataset + dataset->header_size;
	
	while(1)
	{
		if(!get_header_safe(datum, &header))
			break;
		
		if(datum_type < 0 && type < 0)
		{
			/*
			 * If the datum type is not in range, assume the guy want each datum
			 */
			*datum_result = datum;
			break;
		}
		else if((type == header.type || type == -1) && 
		        (datum_type == header.datum_type || datum_type == -1))
		{
			/*
			 * If the type and the datum type searched correspond,
			 * then return this datum
			 */
			*datum_result = datum;
			break;
		}
		
		datum += header.datum_size;
		
		memset(&header, 0, sizeof(datum_header_safe_t));
	}
	
	xprintf(L_DEBUG, "Going out of get_next_datum\n");
	
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
	
	if(!datum_types_prop[header.datum_type].has_nested_datum)
		return FALSE;
	
	*datum_nested = (char*)datum + datum_types_prop[header.datum_type].size_header;
	
	return TRUE;
}


/**
 * Retrieve a datum nested into another one with a specific type
 * 
 * @param datum Where to find a nested datum
 * @param datum_type The datum of the searched datum
 * @param datum_nested The datum resulted
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_nested_datumtype(void* datum, datum_t datum_type, void** datum_nested)
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
	while(nested_header.datum_type != datum_type)
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
 * Safely check of the datum type
 * 
 * @param datum The datum to validate
 * @param datum_type The datum type to find
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int datum_type_must_be(void* datum, datum_t datum_type)
{
	// Check parameters
	if(!datum)
		return FALSE;
	
	datum_header_safe_t header;
	
	if(!get_header_safe(datum, &header))
		return FALSE;
	
	if(header.datum_type == datum_type)
		return TRUE;
	else
		return FALSE;
}


/**
 * Check if a clear key is stored in data
 * 
 * @param metadata The metadata where to look
 * @param vmk_datum The VMK datum of the clear key if found
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int has_clear_key(void* dataset, datum_vmk_t** vmk_datum)
{
	if(!dataset)
		return FALSE;
	
	*vmk_datum = NULL;
	
	xprintf(L_DEBUG, "Entering has_clear_key. Returning result of get_vmk_datum_from_range with range between 0x00 and 0xff\n");
	
	return get_vmk_datum_from_range(dataset, 0x00, 0xff, (void**)vmk_datum);
}

