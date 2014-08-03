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
#include "fvek.h"



/**
 * Get the FVEK from the VMK
 * 
 * @param dataset The metadata's dataset used
 * @param vmk_datum The datum of type 1 containing the VMK
 * @param fvek_datum The FVEK datum KEY structure
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_fvek(bitlocker_dataset_t* dataset, void* vmk_datum, void** fvek_datum)
{
	// Check parameters
	if(!dataset)
		return FALSE;
	
	
	void* vmk_key = NULL;
	size_t vmk_key_size = 0;
	
	unsigned int fvek_size = 0;
	
	
	/* First get the AES-CCM datum where the FVEK is */
	if(!get_next_datum(dataset, 3, 5, 0, fvek_datum))
	{
		xprintf(L_CRITICAL, "Error in finding the AES_CCM datum including the VMK. Internal failure, abort.\n");
		return FALSE;
	}
	
	/* Check if the VMK datum is of type KEY (1) */
	if(!datum_type_must_be(vmk_datum, 1))
	{
		xprintf(L_CRITICAL, "Error, the provided VMK datum's type is incorrect. Abort.\n");
		return FALSE;
	}
	
	/* Then extract the real key in the VMK key structure */
	if(!get_payload_safe(vmk_datum, &vmk_key, &vmk_key_size))
	{
		xprintf(L_CRITICAL, "Error getting the key included into the VMK key structure. Internal failure, abort.\n");
		return FALSE;
	}
	
	/* Finally decrypt the FVEK with the VMK */
	if(!decrypt_key((datum_aes_ccm_t*)*fvek_datum, vmk_key, fvek_datum, &fvek_size))
	{
		if(*fvek_datum)
		{
			xprintf(L_ERROR, "FVEK found (but not good it seems):\n");
			hexdump(L_ERROR, *fvek_datum, fvek_size);
		}
		
		xprintf(L_CRITICAL, "Can't decrypt correctly the FVEK. Abort.\n");
		xfree(*fvek_datum);
		return FALSE;
	}
	
	xfree(vmk_key);
	
	xprintf(L_DEBUG, "=========================[ FVEK ]=========================\n");
	print_one_datum(L_DEBUG, *fvek_datum);
	xprintf(L_DEBUG, "==========================================================\n");
	
	return TRUE;
}


/**
 * Build the FVEK datum using the FVEK file.
 * The expected format is:
 * - 2 bytes for the encryption method used (AES 128/256 bits, with or without
 * diffuser). These two bytes are between 0x8000 -> 0x8003 included, {@see
 * cipher_types@datums.h}.
 * - 512 bytes that are usable directly in init_keys()@dislocker.c
 * 
 * @param cfg The configuration structure, therefore having the FVEK file
 * @param fvek_datum The FVEK datum KEY structure
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int build_fvek_from_file(dis_config_t* cfg, void** fvek_datum)
{
	if(!cfg)
		return FALSE;
	
	
	off_t actual_size   = -1;
	int   file_fd = -1;
	datum_key_t* datum_key = NULL;
	
	char enc_method[2]  = {0,};
	char fvek_keys[64] = {0,};
	
	off_t expected_size = sizeof(enc_method) + sizeof(fvek_keys);
	
	
	file_fd = xopen(cfg->fvek_file, O_RDONLY);
	
	/* Check the file's size */
	actual_size = xlseek(file_fd, 0, SEEK_END);
	
	if(actual_size != expected_size)
	{
		xprintf(L_ERROR, "Wrong FVEK file size, expected %d but has %d\n",
		        expected_size, actual_size);
		return FALSE;
	}
	
	/* Read everything */
	xlseek(file_fd, 0, SEEK_SET);
	xread(file_fd, enc_method, sizeof(enc_method));
	xread(file_fd, fvek_keys,  sizeof(fvek_keys));
	
	
	/* Create the FVEK datum */
	*fvek_datum = xmalloc(sizeof(datum_key_t) + sizeof(fvek_keys));
	
	/* ... create the header */
	datum_key = *fvek_datum;
	datum_key->header.datum_size = sizeof(datum_key_t) + sizeof(fvek_keys);
	datum_key->header.type       = 3;
	datum_key->header.datum_type = DATUM_KEY;
	datum_key->header.error_status = 1;
	
	datum_key->algo = *(cipher_t*)enc_method;
	datum_key->padd = 0;
	
	/* ... copy the keys */
	memcpy((char*) *fvek_datum + sizeof(datum_key_t), fvek_keys, sizeof(fvek_keys));
	
	
	return TRUE;
}
