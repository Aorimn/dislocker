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


#include "encryption/decrypt.h"
#include "vmk.h"



/**
 * Get the VMK datum using a clear key
 * 
 * @param dataset The dataset where a clear key is assumed to be
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_clearkey(bitlocker_dataset_t* dataset, void** vmk_datum)
{
	// Check parameters
	if(!dataset)
		return FALSE;
	
	uint8_t* recovery_key = NULL;
	size_t rk_size = 0;
	
	int result = FALSE;
	
	char* type_str = datumtypestr(DATUM_KEY);
	
	
	/* Search for a clear key */
	if(!has_clear_key(dataset, (datum_vmk_t**)vmk_datum))
	{
		xprintf(L_ERROR, "No clear key found. Use a different method.\n");
		*vmk_datum = NULL;
		return FALSE;
	}
	
	xprintf(L_DEBUG, "============[ There's a clear key here! ]============\n");
	print_one_datum(L_DEBUG, *vmk_datum);
	xprintf(L_DEBUG, "==================[ Clear key end ]==================\n");
	
	/* Get the clear key */
	void* key_datum = NULL;
	if(!get_nested_datumtype(*vmk_datum, DATUM_KEY, &key_datum) || !key_datum)
	{
		xprintf(L_ERROR, "Error looking for the nested datum type %hd (%s) in the VMK one. Internal failure, abort.\n", DATUM_KEY, type_str);
		xfree(type_str);
		*vmk_datum = NULL;
		return FALSE;
	}
	
	if(!get_payload_safe(key_datum, (void**)&recovery_key, &rk_size))
	{
		xprintf(L_ERROR, "Error getting the key to decrypt VMK from the datum %s. Internal failure, abort.\n", type_str);
		xfree(type_str);
		*vmk_datum = NULL;
		return FALSE;
	}
	
	xfree(type_str);
	
	/* Get the encrypted VMK which will be decrypted with the previously found clear key */
	void* aesccm_datum = NULL;
	if(!get_nested_datumtype(*vmk_datum, DATUM_AES_CCM, &aesccm_datum))
	{
		type_str = datumtypestr(DATUM_AES_CCM);
		xprintf(L_ERROR, "Error in finding the %s including the VMK. Internal failure, abort.\n", type_str);
		xfree(type_str);
		xfree(recovery_key);
		*vmk_datum = NULL;
		return FALSE;
	}
	
	/* Run the decryption */
	result = get_vmk((datum_aes_ccm_t*)aesccm_datum, recovery_key, rk_size, (datum_key_t**)vmk_datum);
	
	xfree(recovery_key);
	
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
int get_vmk(datum_aes_ccm_t* vmk_datum, uint8_t* recovery_key, size_t key_size, datum_key_t** vmk)
{
	// Check parameters
	if(!vmk_datum || !recovery_key || key_size == 0)
		return FALSE;
	
	unsigned int vmk_size = 0;
	
	xprintf(L_DEBUG, "=====================[ ENCRYPTED VMK ]====================\n");
	print_one_datum(L_DEBUG, *vmk);
	xprintf(L_DEBUG, "==========================================================\n");
	xprintf(L_DEBUG, "=====================[ RECOVERY KEY ]=====================\n");
	hexdump(L_DEBUG, recovery_key, key_size);
	xprintf(L_DEBUG, "==========================================================\n");
	
	if(!decrypt_key((datum_aes_ccm_t*)vmk_datum, recovery_key, (void**)vmk, &vmk_size))
	{
		if(*vmk)
		{
			xprintf(L_INFO, "VMK found (but not good it seems):\n");
			hexdump(L_INFO, (void*)*vmk, vmk_size);
			xfree(*vmk);
			*vmk = NULL;
		}
		
		xprintf(L_ERROR, "Can't decrypt correctly the VMK. Abort.\n");
		return FALSE;
	}
	
	
	if(!*vmk)
	{
		xprintf(L_ERROR, "Can't decrypt VMK, abort.\n");
		return FALSE;
	}
	
	
	xprintf(L_DEBUG, "==========================[ VMK ]=========================\n");
	print_one_datum(L_DEBUG, *vmk);
	xprintf(L_DEBUG, "==========================================================\n");
	
	
	return TRUE;
}



/**
 * Retrieve the VMK datum associated to a known GUID
 * 
 * @param dataset The dataset where to look for the datum
 * @param guid The GUID of the VMK datum to find
 * @param vmk_datum The found datum
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_datum_from_guid(void* dataset, guid_t guid, void** vmk_datum)
{
	// Check parameters
	if(!dataset || !guid)
		return FALSE;
	
	*vmk_datum = NULL;
	
	while(1)
	{
		if(!get_next_datum(dataset, 2, DATUM_VMK, *vmk_datum, vmk_datum))
		{
			*vmk_datum = NULL;
			return FALSE;
		}
		
		if(check_match_guid((*(datum_vmk_t**)vmk_datum)->guid, guid))
			return TRUE;
	}
}


/**
 * Retrieve the VMK datum associated to priority range
 * The priority is determined with the last two bytes of a VMK datum's nonce
 * 
 * @param dataset The dataset where to look for the datum
 * @param min_range The minimal range to search for
 * @param max_range The maximal range to search for
 * @param vmk_datum The found datum
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_datum_from_range(void* dataset, uint16_t min_range, uint16_t max_range, void** vmk_datum)
{
	// Check parameters
	if(!dataset)
		return FALSE;
	
	uint16_t datum_range = 0;
	
	*vmk_datum = NULL;
	
	while(1)
	{
		if(!get_next_datum(dataset, 2, DATUM_VMK, *vmk_datum, vmk_datum))
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

