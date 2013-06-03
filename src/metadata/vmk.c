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
#include "encryption/decrypt.h"
#include "accesses/bek/read_bekfile.h"
#include "accesses/rp/recovery_password.h"
#include "accesses/user_pass/user_pass.h"
#include "vmk.h"


/* This prototype is for internal use only */
static int get_vmk(datum_aes_ccm_t* vmk_datum, uint8_t* recovery_key,
				   size_t key_size, datum_key_t** vmk);



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
		*vmk_datum = NULL;
		return FALSE;
	}
	
	/* Run the decryption */
	result = get_vmk((datum_aes_ccm_t*)aesccm_datum, recovery_key, rk_size, (datum_key_t**)vmk_datum);
	
	xfree(recovery_key);
	
	return result;
}


/**
 * Get the VMK datum using a recovery password
 * 
 * @param dataset The dataset where a clear key is assumed to be
 * @param cfg The configuration structure
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_rp(bitlocker_dataset_t* dataset, dis_config_t* cfg, void** vmk_datum)
{
	// Check parameters
	if(!dataset || !cfg)
		return FALSE;
	
	uint8_t* recovery_key = NULL;
	uint8_t salt[16] = {0,};
	
	int result = FALSE;
	
	/* If the recovery password wasn't provide, ask for it */
	if(!cfg->recovery_password)
		if(!prompt_rp(&cfg->recovery_password))
		{
			xprintf(L_ERROR, "Cannot get valid recovery password. Abort.\n");
			return FALSE;
		}
	
	
	xprintf(L_DEBUG, "Using the recovery password: '%s'.\n",
	                (char *)cfg->recovery_password);
	
	
	/*
	 * We need a salt contained in the VMK datum associated to the recovery
	 * password, so go get this salt and the VMK datum first
	 * We use here the range which should be upper (or equal) than 0x800
	 */
	if(!get_vmk_datum_from_range((void*)dataset, 0x800, 0xfff, (void**)vmk_datum))
	{
		xprintf(L_ERROR, "Error, can't find a valid and matching VMK datum. Abort.\n");
		*vmk_datum = NULL;
		return FALSE;
	}
	
	
	/*
	 * We have the datum containing other data, so get in there and take the
	 * nested one with type 3 (stretch key)
	 */
	void* stretch_datum = NULL;
	if(!get_nested_datumtype(*vmk_datum, DATUM_STRETCH_KEY, &stretch_datum) || !stretch_datum)
	{
		char* type_str = datumtypestr(DATUM_STRETCH_KEY);
		xprintf(L_ERROR, "Error looking for the nested datum of type %hd (%s) in the VMK one. "
		                 "Internal failure, abort.\n", DATUM_STRETCH_KEY, type_str);
		xfree(type_str);
		*vmk_datum = NULL;
		return FALSE;
	}
	
	
	/* The salt is in here, don't forget to keep it somewhere! */
	memcpy(salt, ((datum_stretch_key_t*)stretch_datum)->salt, 16);
	
	
	/* Get data which can be decrypted with this password */
	void* aesccm_datum = NULL;
	if(!get_nested_datumtype(*vmk_datum, DATUM_AES_CCM, &aesccm_datum) || !aesccm_datum)
	{
		xprintf(L_ERROR, "Error finding the AES_CCM datum including the VMK. Internal failure, abort.\n");
		*vmk_datum = NULL;
		return FALSE;
	}
	
	
	/*
	 * We have all the things we need to compute the intermediate key from
	 * the recovery password, so do it!
	 */
	recovery_key = xmalloc(32 * sizeof(uint8_t));

	if(!intermediate_key(cfg->recovery_password, salt, recovery_key))
	{
		xprintf(L_ERROR, "Error computing the recovery password to the recovery key. Abort.\n");
		*vmk_datum = NULL;
		xfree(recovery_key);
		return FALSE;
	}
	
	/* We don't need the recovery_password anymore */
	memclean((char*)cfg->recovery_password, strlen((char*)cfg->recovery_password));
	cfg->recovery_password = NULL;
	
	/* As the computed key length is always the same, use a direct value */
	result = get_vmk((datum_aes_ccm_t*)aesccm_datum, recovery_key, 32, (datum_key_t**)vmk_datum);
	
	xfree(recovery_key);
	
	return result;
}


/**
 * Get the VMK datum using a bek file (external key)
 * 
 * @param dataset The dataset of BitLocker's metadata on the volume
 * @param cfg The configuration structure
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_bekfile(bitlocker_dataset_t* dataset, dis_config_t* cfg, void** vmk_datum)
{
	// Check parameters
	if(!dataset || !cfg)
		return FALSE;
	
	guid_t key_guid = {0,};
	char rec_id[37] = {0,};
	
	bitlocker_dataset_t* bek_dataset = NULL;
	uint8_t* recovery_key = NULL;
	size_t rk_size = 0;
	
	int result = FALSE;
	int fd_bek = 0;
	
	
	if(cfg->bek_file)
	{
		/* Check if the bek file exists */
		fd_bek = xopen(cfg->bek_file, O_RDONLY);	
	}
	else
	{
		xprintf(L_ERROR, "Using bekfile method (USB) but missing the bekfile name. Abort.\n");
		return FALSE;
	}
	
	xprintf(L_INFO, "Using the bekfile '%s' to decrypt the VMK.\n",
	                cfg->bek_file);
	
	/*
	 * We need the recovery key id which can be found in the bek file
	 * to find its match in a datum of the volume's metadata
	 */
	get_bek_dataset(fd_bek, (void**)&bek_dataset);
	
	/* We have what we wanted, so close the file */
	xclose(fd_bek);
	
	
	/* Get the external datum */
	get_next_datum(bek_dataset, -1, DATUM_EXTERNAL_KEY, NULL, vmk_datum);
	if(bek_dataset)
		memclean(bek_dataset, bek_dataset->size);
	
	
	/* Check the result datum */
	if(!*vmk_datum || !datum_type_must_be(*vmk_datum, DATUM_EXTERNAL_KEY))
	{
		xprintf(L_ERROR, "Error processing the bekfile: datum of type 9 not found. Internal failure, abort.\n");
		*vmk_datum = NULL;
		return FALSE;
	}
	
	/* Now that we are sure of the type, take care of copying the recovery key id */
	datum_external_t* datum_exte = (datum_external_t*) *vmk_datum;
	memcpy(key_guid, datum_exte->guid, 16);
	
	format_guid(key_guid, rec_id);
	xprintf(L_INFO, "Bekfile GUID found: '%s', looking for the same in metadata...\n", rec_id);
	
	/* Grab the datum nested in the last, we will need it to decrypt the VMK */
	if(!get_nested_datumtype(*vmk_datum, DATUM_KEY, vmk_datum) || !*vmk_datum)
	{
		xprintf(L_ERROR, "Error processing the bekfile: no nested datum found. Internal failure, abort.\n");
		*vmk_datum = NULL;
		return FALSE;
	}
	
	if(!get_payload_safe(*vmk_datum, (void**)&recovery_key, &rk_size))
	{
		xprintf(L_ERROR, "Error getting the key to decrypt VMK from the bekfile. Internal failure, abort.\n");
		*vmk_datum = NULL;
		return FALSE;
	}
	
	
	/*
	 * Now that we have the key to decrypt the VMK, we need to
	 * find the VMK datum in the BitLocker metadata in order to
	 * decrypt the VMK using this already found key in the bekfile
	 */
	if(!get_vmk_datum_from_guid((void*)dataset, key_guid, vmk_datum))
	{
		format_guid(key_guid, rec_id);
		
		xprintf(L_ERROR,
				"\n\tError, can't find a valid and matching VMK datum.\n"
				"\tThe GUID researched was '%s', check if you have the right bek file.\n"
				"\tAbort.\n",
			rec_id
		);
		*vmk_datum = NULL;
		return FALSE;
	}
	
	xprintf(L_INFO, "VMK datum of id '%s' found. Trying to reach the Key datum...\n", rec_id);
	
	
	/*
	 * We have the datum containing other data, so get in there and take the
	 * nested one with type 5 (aes-ccm)
	 */
	if(!get_nested_datumtype(*vmk_datum, DATUM_AES_CCM, vmk_datum))
	{
		xprintf(L_ERROR, "Error looking for the nested datum in the VMK one. Internal failure, abort.\n");
		*vmk_datum = NULL;
		return FALSE;
	}
	
	
	xprintf(L_INFO, "Key datum found and payload extracted!\n");
	
	result = get_vmk((datum_aes_ccm_t*)*vmk_datum, recovery_key, rk_size, (datum_key_t**)vmk_datum);
	
	xfree(recovery_key);
	
	return result;
}


/**
 * Get the VMK datum using a user password
 * 
 * @param dataset The dataset of BitLocker's metadata on the volume
 * @param cfg The configuration structure
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_user_pass(bitlocker_dataset_t* dataset, dis_config_t* cfg, void** vmk_datum)
{
	// Check parameters
	if(!dataset || !cfg)
		return FALSE;
	
	uint8_t user_hash[32] = {0,};
	uint8_t salt[16]      = {0,};
	
	/* If the user password wasn't provide, ask for it */
	if(!cfg->user_password)
		if(!prompt_up(&cfg->user_password))
		{
			xprintf(L_ERROR, "Cannot get valid user password. Abort.\n");
			return FALSE;
		}
		
	xprintf(L_DEBUG, "Using the user password: '%s'.\n",
	                (char *)cfg->user_password);
	
	
	/*
	 * We need a salt contained in the VMK datum associated to the recovery
	 * password, so go get this salt and the VMK datum first
	 * We use here the range which should be equal to 0x2000
	 * There may be another mean to find the correct datum, but I don't see
	 * another one here
	 */
	if(!get_vmk_datum_from_range((void*)dataset, 0x2000, 0x2000, (void**)vmk_datum))
	{
		xprintf(L_ERROR, "Error, can't find a valid and matching VMK datum. Abort.\n");
		*vmk_datum = NULL;
		return FALSE;
	}
	
	
	/*
	 * We have the datum containing other data, so get in there and take the
	 * nested one with type 3 (stretch key)
	 */
	void* stretch_datum = NULL;
	if(!get_nested_datumtype(*vmk_datum, DATUM_STRETCH_KEY, &stretch_datum) || !stretch_datum)
	{
		char* type_str = datumtypestr(DATUM_STRETCH_KEY);
		xprintf(L_ERROR, "Error looking for the nested datum of type %hd (%s) in the VMK one. "
		                 "Internal failure, abort.\n", DATUM_STRETCH_KEY, type_str);
		xfree(type_str);
		*vmk_datum = NULL;
		return FALSE;
	}
	
	
	/* The salt is in here, don't forget to keep it somewhere! */
	memcpy(salt, ((datum_stretch_key_t*)stretch_datum)->salt, 16);
	
	
	/* Get data which can be decrypted with this password */
	void* aesccm_datum = NULL;
	if(!get_nested_datumtype(*vmk_datum, DATUM_AES_CCM, &aesccm_datum) || !aesccm_datum)
	{
		xprintf(L_ERROR, "Error finding the AES_CCM datum including the VMK. Internal failure, abort.\n");
		*vmk_datum = NULL;
		return FALSE;
	}
	
	
	/*
	 * We have all the things we need to compute the intermediate key from
	 * the user password, so do it!
	 */
	if(!user_key(cfg->user_password, salt, user_hash))
	{
		xprintf(L_CRITICAL, "Can't stretch the user password, aborting.\n");
		*vmk_datum = NULL;
		return FALSE;
	}
	
	/* We don't need the user password anymore */
	memclean((char*)cfg->user_password, strlen((char*)cfg->user_password));
	cfg->user_password = NULL;
	
	/* As the computed key length is always the same, use a direct value */
	return get_vmk((datum_aes_ccm_t*)aesccm_datum, user_hash, 32, (datum_key_t**)vmk_datum);;
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
static int get_vmk(datum_aes_ccm_t* vmk_datum, uint8_t* recovery_key, size_t key_size, datum_key_t** vmk)
{
	// Check parameters
	if(!vmk_datum || !recovery_key || key_size == 0)
		return FALSE;
	
	unsigned int vmk_size = 0;
	
	xprintf(L_INFO, "=====================[ ENCRYPTED VMK ]====================\n");
	print_one_datum(L_INFO, *vmk);
	xprintf(L_INFO, "==========================================================\n");
	xprintf(L_INFO, "=====================[ RECOVERY KEY ]=====================\n");
	hexdump(L_INFO, recovery_key, key_size);
	xprintf(L_INFO, "==========================================================\n");
	
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
	
	
	xprintf(L_INFO, "==========================[ VMK ]=========================\n");
	print_one_datum(L_INFO, *vmk);
	xprintf(L_INFO, "==========================================================\n");
	
	
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

