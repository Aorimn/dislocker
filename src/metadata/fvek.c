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
 * @param fvek_datum 
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
		return FALSE;
	}
	
	xfree(vmk_key);
	
	xprintf(L_INFO, "=========================[ FVEK ]=========================\n");
	print_one_datum(L_INFO, *fvek_datum);
	xprintf(L_INFO, "==========================================================\n");
	
	return TRUE;
}
