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

#include "dislocker/common.h"
#include "dislocker/metadata/metadata.priv.h"
#include "dislocker/metadata/vmk.h"
#include "dislocker/accesses/bek/bekfile.h"



/**
 * Get the VMK datum using a bek file (external key)
 *
 * @param dataset The dataset of BitLocker's metadata on the volume
 * @param cfg The configuration structure
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_bekfile(dis_metadata_t dis_meta,
                         dis_config_t* cfg,
                         void** vmk_datum)
{
	return get_vmk_from_bekfile2(dis_meta, cfg->bek_file, vmk_datum);
}


/**
 * Get the VMK datum using a bek file (external key)
 *
 * @param dataset The dataset of BitLocker's metadata on the volume
 * @param bek_file The path to the .BEK file to use
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_bekfile2(dis_metadata_t dis_meta,
                          char* bek_file,
                          void** vmk_datum)
{
	// Check parameters
	if(!dis_meta || !vmk_datum)
		return FALSE;

	guid_t key_guid = {0,};
	char rec_id[37] = {0,};

	bitlocker_dataset_t* bek_dataset = NULL;
	uint8_t* recovery_key = NULL;
	size_t rk_size = 0;

	int result = FALSE;
	int fd_bek = 0;


	if(bek_file)
	{
		/* Check if the bek file exists */
		fd_bek = dis_open(bek_file, O_RDONLY);
		if(fd_bek < 0)
		{
			dis_printf(L_ERROR, "Cannot open FVEK file (%s)\n", bek_file);
			return FALSE;
		}
	}
	else
	{
		dis_printf(
			L_ERROR,
			"Using bekfile method (USB) but missing the bekfile name. Abort.\n"
		);
		return FALSE;
	}

	dis_printf(
		L_INFO,
		"Using the bekfile '%s' to decrypt the VMK.\n",
		bek_file
	);

	/*
	 * We need the recovery key id which can be found in the bek file
	 * to find its match in a datum of the volume's metadata
	 */
	if(!get_bek_dataset(fd_bek, (void**) &bek_dataset))
	{
		dis_printf(L_ERROR, "Unable to retrieve the dataset. Abort.\n");
		dis_close(fd_bek);
		return FALSE;
	}

	/* We have what we wanted, so close the file */
	dis_close(fd_bek);


	/* Get the external datum */
	void* dataset = dis_metadata_set_dataset(dis_meta, bek_dataset);
	get_next_datum(
		dis_meta,
		UINT16_MAX,
		DATUMS_VALUE_EXTERNAL_KEY,
		NULL,
		vmk_datum
	);
	dis_metadata_set_dataset(dis_meta, dataset);

	/* Check the result datum */
	if(!*vmk_datum ||
	   !datum_value_type_must_be(*vmk_datum, DATUMS_VALUE_EXTERNAL_KEY))
	{
		dis_printf(
			L_ERROR,
			"Error processing the bekfile: datum of type %hd not found. "
			"Internal failure, abort.\n",
			DATUMS_VALUE_EXTERNAL_KEY
		);
		*vmk_datum = NULL;
		memclean(bek_dataset, bek_dataset->size);
		return FALSE;
	}

	/* Now that we are sure of the type, take care of copying the recovery key id */
	datum_external_t* datum_exte = (datum_external_t*) *vmk_datum;
	memcpy(key_guid, datum_exte->guid, 16);

	format_guid(key_guid, rec_id);
	dis_printf(
		L_INFO,
		"Bekfile GUID found: '%s', looking for the same in metadata...\n",
		rec_id
	);

	/* Grab the datum nested in the last, we will need it to decrypt the VMK */
	if(!get_nested_datumvaluetype(*vmk_datum, DATUMS_VALUE_KEY, vmk_datum) ||
	   !*vmk_datum)
	{
		dis_printf(
			L_ERROR,
			"Error processing the bekfile: no nested datum found. "
			"Internal failure, abort.\n"
		);
		*vmk_datum = NULL;
		memclean(bek_dataset, bek_dataset->size);
		return FALSE;
	}

	if(!get_payload_safe(*vmk_datum, (void**) &recovery_key, &rk_size))
	{
		dis_printf(
			L_ERROR,
			"Error getting the key to decrypt VMK from the bekfile. "
			"Internal failure, abort.\n"
		);
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
	if(!get_vmk_datum_from_guid(dis_meta, key_guid, vmk_datum))
	{
		format_guid(key_guid, rec_id);

		dis_printf(
			L_ERROR,
			"\n\tError, can't find a valid and matching VMK datum.\n"
			"\tThe GUID researched was '%s', check if you have the right "
			"bek file for the right volume.\n"
			"\tAbort.\n",
			rec_id
		);
		*vmk_datum = NULL;
		dis_free(recovery_key);
		return FALSE;
	}

	dis_printf(
		L_INFO,
		"VMK datum of id '%s' found. Trying to reach the Key datum...\n",
		rec_id
	);


	/*
	 * We have the datum containing other data, so get in there and take the
	 * nested one with type 5 (aes-ccm)
	 */
	if(!get_nested_datumvaluetype(*vmk_datum, DATUMS_VALUE_AES_CCM, vmk_datum))
	{
		dis_printf(
			L_ERROR,
			"Error looking for the nested datum in the VMK one. "
			"Internal failure, abort.\n"
		);
		*vmk_datum = NULL;
		dis_free(recovery_key);
		return FALSE;
	}


	dis_printf(L_INFO, "Key datum found and payload extracted!\n");

	result = get_vmk(
		(datum_aes_ccm_t*) *vmk_datum,
		recovery_key,
		rk_size,
		(datum_key_t**) vmk_datum
	);

	dis_free(recovery_key);

	return result;
}


/**
 * Get the dataset present in a .BEK file
 *
 * @param fd The file descriptor to the .BEK file
 * @param bek_dataset The extracted dataset
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_bek_dataset(int fd, void** bek_dataset)
{
	if(!bek_dataset)
	{
		dis_printf(L_ERROR, "Invalid parameter given to get_bek_dataset().\n");
		return FALSE;
	}

	bitlocker_dataset_t dataset;

	/* Read the dataset header */
	ssize_t nb_read = dis_read(fd, &dataset, sizeof(bitlocker_dataset_t));

	// Check if we read all we wanted
	if(nb_read != sizeof(bitlocker_dataset_t))
	{
		dis_printf(
			L_ERROR,
			"get_bek_dataset::Error, not all byte read (bek dataset header).\n"
		);
		return FALSE;
	}

	if(dataset.size <= sizeof(bitlocker_dataset_t))
	{
		dis_printf(
			L_ERROR,
			"get_bek_dataset::Error, dataset size < dataset header size.\n"
		);
		return FALSE;
	}

	*bek_dataset = dis_malloc(dataset.size);

	memset(*bek_dataset, 0, dataset.size);
	memcpy(*bek_dataset, &dataset, sizeof(bitlocker_dataset_t));

	size_t rest = dataset.size - sizeof(bitlocker_dataset_t);

	/* Read the data included in the dataset */
	nb_read = dis_read(fd, *bek_dataset + sizeof(bitlocker_dataset_t), rest);

	// Check if we read all we wanted
	if((size_t) nb_read != rest)
	{
		dis_printf(
			L_ERROR,
			"get_bek_dataset::Error, not all byte read (bek dataset content).\n"
		);
		dis_free(*bek_dataset);
		return FALSE;
	}

	return TRUE;
}
