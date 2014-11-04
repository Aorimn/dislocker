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
/*
 * BitLocker Encryption Key (BEK) structure reader.
 *
 * Ref:
 * - http://jessekornblum.com/publications/di09.pdf
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

#include "common.h"
#include "metadata/metadata.h"
#include "metadata/vmk.h"
#include "bekfile.h"



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
	if(!get_bek_dataset(fd_bek, (void**)&bek_dataset))
	{
		xprintf(L_ERROR, "Unable to retrieve the dataset. Abort.\n");
		xclose(fd_bek);
		return FALSE;
	}
	
	/* We have what we wanted, so close the file */
	xclose(fd_bek);
	
	
	/* Get the external datum */
	get_next_datum(bek_dataset, -1, DATUM_EXTERNAL_KEY, NULL, vmk_datum);
	
	/* Check the result datum */
	if(!*vmk_datum || !datum_type_must_be(*vmk_datum, DATUM_EXTERNAL_KEY))
	{
		xprintf(L_ERROR, "Error processing the bekfile: datum of type 9 not found. Internal failure, abort.\n");
		*vmk_datum = NULL;
		memclean(bek_dataset, bek_dataset->size);
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
		memclean(bek_dataset, bek_dataset->size);
		return FALSE;
	}
	
	if(!get_payload_safe(*vmk_datum, (void**)&recovery_key, &rk_size))
	{
		xprintf(L_ERROR, "Error getting the key to decrypt VMK from the bekfile. Internal failure, abort.\n");
		*vmk_datum = NULL;
		memclean(bek_dataset, bek_dataset->size);
		return FALSE;
	}
	
	memclean(bek_dataset, bek_dataset->size);
	
	
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
				"\tThe GUID researched was '%s', check if you have the right bek file for the right volume.\n"
				"\tAbort.\n",
			rec_id
		);
		*vmk_datum = NULL;
		xfree(recovery_key);
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
		xfree(recovery_key);
		return FALSE;
	}
	
	
	xprintf(L_INFO, "Key datum found and payload extracted!\n");
	
	result = get_vmk((datum_aes_ccm_t*)*vmk_datum, recovery_key, rk_size, (datum_key_t**)vmk_datum);
	
	xfree(recovery_key);
	
	return result;
}


/**
 * TODO
 */
int get_bek_dataset(int fd, void** bek_dataset)
{
	if(!bek_dataset)
	{
		xprintf(L_ERROR, "Invalid parameter given to get_bek_dataset().\n");
		return FALSE;
	}
	
	bitlocker_dataset_t dataset;
	
	/* Read the dataset header */
	ssize_t nb_read = xread(fd, &dataset, sizeof(bitlocker_dataset_t));
	
	// Check if we read all we wanted
	if(nb_read != sizeof(bitlocker_dataset_t))
	{
		xprintf(L_ERROR, "get_bek_dataset::Error, not all byte read (bek dataset header).\n");
		return FALSE;
	}
	
	if(dataset.size <= sizeof(bitlocker_dataset_t))
	{
		xprintf(L_ERROR, "get_bek_dataset::Error, dataset size < dataset header size.\n");
		return FALSE;
	}
	
	*bek_dataset = xmalloc(dataset.size);
	
	memset(*bek_dataset, 0, dataset.size);
	memcpy(*bek_dataset, &dataset, sizeof(bitlocker_dataset_t));
	
	size_t rest = dataset.size - sizeof(bitlocker_dataset_t);
	
	/* Read the data included in the dataset */
	nb_read = xread(fd, *bek_dataset + sizeof(bitlocker_dataset_t), rest);
	
	// Check if we read all we wanted
	if((size_t) nb_read != rest)
	{
		xprintf(L_ERROR, "get_bek_dataset::Error, not all byte read (bek dataset content).\n");
		xfree(*bek_dataset);
		return FALSE;
	}
	
	return TRUE;
}
