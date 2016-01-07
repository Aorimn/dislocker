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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dislocker/metadata/datums.h"
#include "dislocker/encryption/decrypt.h"
#include "dislocker/metadata/fvek.h"
#include "dislocker/metadata/metadata.priv.h"



/**
 * Get the FVEK from the VMK
 *
 * @param dis_metadata The metadata structure
 * @param vmk_datum The datum of type 1 containing the VMK
 * @param fvek_datum The FVEK datum KEY structure
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_fvek(dis_metadata_t dis_meta, void* vmk_datum, void** fvek_datum)
{
	// Check parameters
	if(!dis_meta)
		return FALSE;

	void* vmk_key = NULL;
	size_t vmk_key_size = 0;
	datum_aes_ccm_t* fvek = NULL;

	unsigned int fvek_size = 0;
	unsigned int header_size = 0;


	/* First get the AES-CCM datum where the FVEK is */
	if(!get_next_datum(
			dis_meta,
			DATUMS_ENTRY_FVEK,
			DATUMS_VALUE_AES_CCM,
			0,
			fvek_datum
	))
	{
		dis_printf(
			L_CRITICAL,
			"Error in finding the AES_CCM datum including the VMK. "
			"Internal failure, abort.\n"
		);
		return FALSE;
	}

	/* Check if the VMK datum is of type KEY (1) */
	if(!datum_value_type_must_be(vmk_datum, DATUMS_VALUE_KEY))
	{
		dis_printf(
			L_CRITICAL,
			"Error, the provided VMK datum's type is incorrect. Abort.\n"
		);
		return FALSE;
	}

	/* Then extract the real key in the VMK key structure */
	if(!get_payload_safe(vmk_datum, &vmk_key, &vmk_key_size))
	{
		dis_printf(
			L_CRITICAL,
			"Error getting the key included into the VMK key structure. "
			"Internal failure, abort.\n"
		);
		return FALSE;
	}

	fvek = (datum_aes_ccm_t*)*fvek_datum;
	header_size = datum_value_types_prop[fvek->header.value_type].size_header;
	fvek_size = fvek->header.datum_size - header_size;

	if(vmk_key_size > (size_t) (UINT_MAX / 8))
	{
		dis_printf(
			L_ERROR,
			"VMK size too big, unsupported: %#" F_SIZE_T "\n",
			vmk_key_size
		);
		return FALSE;
	}

	/* Finally decrypt the FVEK with the VMK */
	if(!decrypt_key(
			(unsigned char*) fvek + header_size,
			fvek_size,
			fvek->mac,
			fvek->nonce,
			vmk_key,
			(unsigned int)vmk_key_size * 8,
			fvek_datum
	))
	{
		if(*fvek_datum)
		{
			dis_printf(L_ERROR, "FVEK found (but not good it seems):\n");
			hexdump(L_ERROR, *fvek_datum, fvek_size);
		}

		dis_printf(L_CRITICAL, "Can't decrypt correctly the FVEK. Abort.\n");
		dis_free(*fvek_datum);
		return FALSE;
	}

	dis_free(vmk_key);

	dis_printf(L_DEBUG, "=========================[ FVEK ]=========================\n");
	print_one_datum(L_DEBUG, *fvek_datum);
	dis_printf(L_DEBUG, "==========================================================\n");

	return TRUE;
}


/**
 * Build the FVEK datum using the FVEK file.
 * The expected format is:
 * - 2 bytes for the encryption method used (AES 128/256 bits, with or without
 * diffuser). These two bytes are between 0x8000 -> 0x8003 included, {@see
 * cipher_types@datums.h}.
 * - 512 bytes that are usable directly in init_keys()@outputs/prepare.c
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
	ssize_t rs;

	union {
		cipher_t single;
		char multi[2];
	} enc_method;

	memset(enc_method.multi, 0, 2);
	char fvek_keys[64] = {0,};

	off_t expected_size = sizeof(enc_method) + sizeof(fvek_keys);


	file_fd = dis_open(cfg->fvek_file, O_RDONLY);
	if(file_fd == -1)
	{
		dis_printf(L_ERROR, "Cannot open FVEK file (%s)\n", cfg->fvek_file);
		return FALSE;
	}

	/* Check the file's size */
	actual_size = dis_lseek(file_fd, 0, SEEK_END);

	if(actual_size != expected_size)
	{
		dis_printf(
			L_ERROR,
			"Wrong FVEK file size, expected %d but has %d\n",
			expected_size,
			actual_size
		);
		return FALSE;
	}

	/* Read everything */
	dis_lseek(file_fd, 0, SEEK_SET);
	rs = dis_read(file_fd, enc_method.multi, sizeof(enc_method));
	if(rs != sizeof(enc_method))
	{
		dis_printf(
			L_ERROR,
			"Cannot read whole encryption method in the FVEK file\n"
		);
		return FALSE;
	}
	rs = dis_read(file_fd, fvek_keys,  sizeof(fvek_keys));
	if(rs != sizeof(fvek_keys))
	{
		dis_printf(L_ERROR, "Cannot read whole FVEK keys in the FVEK file\n");
		return FALSE;
	}


	/* Create the FVEK datum */
	*fvek_datum = dis_malloc(sizeof(datum_key_t) + sizeof(fvek_keys));

	/* ... create the header */
	datum_key = *fvek_datum;
	datum_key->header.datum_size = sizeof(datum_key_t) + sizeof(fvek_keys);
	datum_key->header.entry_type = 3;
	datum_key->header.value_type = DATUMS_VALUE_KEY;
	datum_key->header.error_status = 1;

	datum_key->algo = enc_method.single;
	datum_key->padd = 0;

	/* ... copy the keys */
	memcpy((char*) *fvek_datum + sizeof(datum_key_t), fvek_keys, sizeof(fvek_keys));


	return TRUE;
}
