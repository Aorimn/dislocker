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


#include <limits.h>
#include "dislocker/encryption/decrypt.h"
#include "dislocker/metadata/vmk.h"



/**
 * Get the VMK datum using a clear key
 *
 * @param dis_metadata The metadata structure
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_clearkey(dis_metadata_t dis_meta, void** vmk_datum)
{
	// Check parameters
	if(!dis_meta)
		return FALSE;

	uint8_t* recovery_key = NULL;
	size_t rk_size = 0;

	int result = FALSE;

	char* type_str = datumvaluetypestr(DATUMS_VALUE_KEY);


	/* Search for a clear key */
	if(!dis_metadata_has_clear_key(dis_meta, vmk_datum))
	{
		dis_printf(L_ERROR, "No clear key found. Use a different method.\n");
		dis_free(type_str);
		*vmk_datum = NULL;
		return FALSE;
	}

	dis_printf(L_DEBUG, "============[ There's a clear key here! ]============\n");
	print_one_datum(L_DEBUG, *vmk_datum);
	dis_printf(L_DEBUG, "==================[ Clear key end ]==================\n");

	/* Get the clear key */
	void* key_datum = NULL;
	if(!get_nested_datumvaluetype(*vmk_datum, DATUMS_VALUE_KEY, &key_datum) ||
	   !key_datum)
	{
		dis_printf(
			L_ERROR,
			"Error looking for the nested datum type %hd (%s) in the VMK one. "
			"Internal failure, abort.\n",
			DATUMS_VALUE_KEY,
			type_str
		);
		dis_free(type_str);
		*vmk_datum = NULL;
		return FALSE;
	}

	if(!get_payload_safe(key_datum, (void**)&recovery_key, &rk_size))
	{
		dis_printf(
			L_ERROR,
			"Error getting the key to decrypt VMK from the datum %s. "
			"Internal failure, abort.\n",
			type_str
		);
		dis_free(type_str);
		*vmk_datum = NULL;
		return FALSE;
	}

	dis_free(type_str);

	/* Get the encrypted VMK which will be decrypted with the previously found clear key */
	void* aesccm_datum = NULL;
	if(!get_nested_datumvaluetype(
			*vmk_datum,
			DATUMS_VALUE_AES_CCM,
			&aesccm_datum
	))
	{
		type_str = datumvaluetypestr(DATUMS_VALUE_AES_CCM);
		dis_printf(
			L_ERROR,
			"Error in finding the %s including the VMK. "
			"Internal failure, abort.\n",
			type_str
		);
		dis_free(type_str);
		dis_free(recovery_key);
		*vmk_datum = NULL;
		return FALSE;
	}

	/* Run the decryption */
	result = get_vmk(
		(datum_aes_ccm_t*) aesccm_datum,
		recovery_key,
		rk_size,
		(datum_key_t**) vmk_datum
	);

	dis_free(recovery_key);

	return result;
}



/**
 * Final stage to decrypt the VMK, other functions should pass here
 *
 * @param vmk_datum The encrypted VMK datum to decrypt
 * @param recovery_key The key to use to decrypt the encrypted VMK datum
 * @param key_size The key size
 * @param vmk The found datum_key_t containing the decrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk(datum_aes_ccm_t* vmk_datum, uint8_t* recovery_key, size_t key_size,
	datum_key_t** vmk)
{
	// Check parameters
	if(!vmk_datum || !recovery_key || key_size == 0)
		return FALSE;

	unsigned int vmk_size = 0;
	unsigned int header_size = 0;

	dis_printf(L_DEBUG, "=====================[ ENCRYPTED VMK ]====================\n");
	print_one_datum(L_DEBUG, *vmk);
	dis_printf(L_DEBUG, "==========================================================\n");
	dis_printf(L_DEBUG, "=====================[ RECOVERY KEY ]=====================\n");
	hexdump(L_DEBUG, recovery_key, key_size);
	dis_printf(L_DEBUG, "==========================================================\n");

	header_size = datum_value_types_prop[vmk_datum->header.value_type].size_header;
	vmk_size = vmk_datum->header.datum_size - header_size;

	if(key_size > (size_t) (UINT_MAX / 8))
	{
		dis_printf(
			L_ERROR,
			"Recovery key size too big, unsupported: %#" F_SIZE_T "\n",
			key_size
		);
		return FALSE;
	}

	if(!decrypt_key(
			(unsigned char*) vmk_datum + header_size,
			vmk_size,
			vmk_datum->mac,
			vmk_datum->nonce,
			recovery_key,
			(unsigned int)key_size * 8,
			(void**) vmk
	))
	{
		if(*vmk)
		{
			dis_printf(L_INFO, "VMK found (but not good it seems):\n");
			hexdump(L_INFO, (void*)*vmk, vmk_size);
			dis_free(*vmk);
			*vmk = NULL;
		}

		dis_printf(L_ERROR, "Can't decrypt correctly the VMK. Abort.\n");
		return FALSE;
	}


	if(!*vmk)
	{
		dis_printf(L_ERROR, "Can't decrypt VMK, abort.\n");
		return FALSE;
	}


	dis_printf(L_DEBUG, "==========================[ VMK ]=========================\n");
	print_one_datum(L_DEBUG, *vmk);
	dis_printf(L_DEBUG, "==========================================================\n");


	return TRUE;
}



/**
 * Retrieve the VMK datum associated to a known GUID
 *
 * @param dis_metadata The metadata structure
 * @param guid The GUID of the VMK datum to find
 * @param vmk_datum The found datum
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_datum_from_guid(dis_metadata_t dis_meta, guid_t guid,
	void** vmk_datum)
{
	// Check parameters
	if(!dis_meta || !guid)
		return FALSE;

	*vmk_datum = NULL;

	while(1)
	{
		if(!get_next_datum(
				dis_meta,
				DATUMS_ENTRY_VMK,
				DATUMS_VALUE_VMK,
				*vmk_datum,
				vmk_datum
		))
		{
			*vmk_datum = NULL;
			return FALSE;
		}

		if(check_match_guid((*(datum_vmk_t**) vmk_datum)->guid, guid))
			return TRUE;
	}
}


/**
 * Retrieve the VMK datum associated to priority range
 * The priority is determined with the last two bytes of a VMK datum's nonce
 *
 * @param dis_metadata The metadata structure
 * @param min_range The minimal range to search for
 * @param max_range The maximal range to search for
 * @param vmk_datum The found datum
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_datum_from_range(dis_metadata_t dis_meta, uint16_t min_range,
	uint16_t max_range, void** vmk_datum)
{
	// Check parameters
	if(!dis_meta)
		return FALSE;

	uint16_t datum_range = 0;

	*vmk_datum = NULL;

	while(1)
	{
		if(!get_next_datum(
				dis_meta,
				DATUMS_ENTRY_VMK,
				DATUMS_VALUE_VMK,
				*vmk_datum,
				vmk_datum
		))
		{
			*vmk_datum = NULL;
			return FALSE;
		}

		/* The last two bytes of the nonce is used as a priority range */
		memcpy(&datum_range, &((*(datum_vmk_t**)vmk_datum)->nonce[10]), 2);

		if(min_range <= datum_range && datum_range <= max_range)
			return TRUE;
	}
}

