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

#include <pthread.h>

#include "prepare.h"
#include "sectors.h"



/**
 * Getting the real volume size is proving to be quite difficult.
 */
static uint64_t get_volume_size(dis_iodata_t* io_data);



/**
 * Initialize data decryption keys
 * 
 * @param dataset BitLocker dataset
 * @param fvek The entire 32 bytes FVEK, without the KEY structure
 * @param ctx Contexts to initialize, used by AES-CBC for data en/decryption
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int init_keys(bitlocker_dataset_t* dataset, datum_key_t* fvek_datum,
                     contexts_t* ctx)
{
	// Check parameters
	if(!dataset || !fvek_datum || !ctx)
		return FALSE;
	
	uint8_t* fvek    = NULL;
	size_t size_fvek = 0;
	
	if(!get_payload_safe(fvek_datum, (void**)&fvek, &size_fvek))
	{
		xprintf(L_ERROR, "Can't get the FVEK datum payload. Abort.\n");
		return FALSE;
	}
	
	xprintf(L_DEBUG,
	        "FVEK -----------------------------------------------------\n");
	hexdump(L_DEBUG, fvek, size_fvek);
	xprintf(L_DEBUG,
	        "----------------------------------------------------------\n");
	
	/*
	 * It shouldn't be necessary as the algorithms should be the same, but
	 * still, we have a choice, so we do both
	 */
	uint16_t  algo[3] = {dataset->algorithm, fvek_datum->algo, 0};
	uint16_t* palgo   = algo;
	
	while(*palgo != 0)
	{
		switch(*palgo)
		{
			case AES_128_DIFFUSER:
				AES_SETENC_KEY(&ctx->TWEAK_E_ctx, fvek + 0x20, 128);
				AES_SETDEC_KEY(&ctx->TWEAK_D_ctx, fvek + 0x20, 128);
				/* no break on purpose */
			case AES_128_NO_DIFFUSER:
				AES_SETENC_KEY(&ctx->FVEK_E_ctx, fvek, 128);
				AES_SETDEC_KEY(&ctx->FVEK_D_ctx, fvek, 128);
				memclean(fvek, size_fvek);
				return TRUE;
				
			case AES_256_DIFFUSER:
				AES_SETENC_KEY(&ctx->TWEAK_E_ctx, fvek + 0x20, 256);
				AES_SETDEC_KEY(&ctx->TWEAK_D_ctx, fvek + 0x20, 256);
				/* no break on purpose */
			case AES_256_NO_DIFFUSER:
				AES_SETENC_KEY(&ctx->FVEK_E_ctx, fvek, 256);
				AES_SETDEC_KEY(&ctx->FVEK_D_ctx, fvek, 256);
				memclean(fvek, size_fvek);
				return TRUE;
				
			default:
			{
				unsigned long i = (unsigned long)(palgo - algo);
				i /= sizeof(uint16_t);
				xprintf(L_WARNING, "[%lu] Algo not supported: %#hx\n",
				        i, *palgo);
				break;
			}
		}
		
		palgo++;
	}
	
	xprintf(L_ERROR,
	        "Dataset's and FVEK's algorithms not supported: %#hx and %#hx\n",
	        dataset->algorithm, fvek_datum->algo);
	memclean(fvek, size_fvek);
	
	return FALSE;
}


/**
 * Prepare a structure which hold data used for decryption/encryption
 * 
 * @param dis_ctx The dislocker context used everywhere.
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int prepare_crypt(dis_context_t* dis_ctx)
{
	dis_iodata_t* io_data   = &dis_ctx->io_data;
	
	int nb_virt_region      = 0;
	io_data->xinfo          = NULL;
	io_data->sector_size    = io_data->volume_header->sector_size;
	io_data->part_off       = dis_ctx->cfg.offset;
	io_data->decrypt_region = read_decrypt_sectors;
	io_data->encrypt_region = encrypt_write_sectors;
	
	if(pthread_mutex_init(&io_data->mutex_lseek_rw, NULL) != 0)
	{
		xprintf(L_ERROR, "Can't initialize mutex: %s\n", strerror(errno));
		return FALSE;
	}
	
	/*
	 * We need to grab the volume's size from the first sector, so we can
	 * announce it on a getattr call
	 */
	io_data->volume_size = get_volume_size(io_data);
	if(io_data->volume_size == 0)
	{
		xprintf(L_ERROR, "Can't initialize the volume's size\n");
		return FALSE;
	}
	
	xprintf(
		L_INFO,
		"Found volume's size: 0x%1$" F_U64_T " (%1$llu) bytes\n",
		io_data->volume_size
	);
	
	
	/*
	 * Initialize region to report as filled with zeroes, if asked from the NTFS
	 * layer. This is to mimic BitLocker's behaviour.
	 */
	nb_virt_region = end_compute_regions(
		io_data->virt_region,
		io_data->volume_header,
		io_data->metadata
	);
	
	if(nb_virt_region < 0)
	{
		xprintf(
			L_ERROR,
			"Can't compute regions.\n"
		);
		return FALSE;
	}
	
	io_data->nb_virt_region = (size_t) nb_virt_region;
	
	if(io_data->metadata->version == V_SEVEN)
	{
		datum_virtualization_t* datum = NULL;
		if(!get_next_datum(&io_data->metadata->dataset, -1,
		    DATUM_VIRTUALIZATION_INFO, NULL, (void**)&datum))
		{
			char* type_str = datumtypestr(DATUM_VIRTUALIZATION_INFO);
			xprintf(
				L_ERROR,
				"Error looking for the VIRTUALIZATION datum type"
				" %hd (%s). Internal failure, abort.\n",
				DATUM_VIRTUALIZATION_INFO,
				type_str
			);
			xfree(type_str);
			datum = NULL;
			return FALSE;
		}
		io_data->virtualized_size = (off_t)datum->nb_bytes;
		
		xprintf(
			L_DEBUG,
			"Virtualized info size: %#" F_OFF_T "\n",
			io_data->virtualized_size
		);
		
		
		/* Extended info is new to Windows 8 */
		// TODO add check on datum_types_prop's size against datum->header.datum_type
		size_t win7_size   = datum_types_prop[datum->header.datum_type].size_header;
		size_t actual_size = ((size_t)datum->header.datum_size) & 0xffff;
		if(actual_size > win7_size)
		{
			io_data->xinfo = &datum->xinfo;
			xprintf(L_DEBUG, "Got extended info\n");
		}
	}
	
	
	return TRUE;
}


/**
 * Retrieve the volume size from the first sector.
 * 
 * @param volume_header The partition MBR to look at. NTFS or FVE, np
 * @return The volume size or 0, which indicates the size couldn't be retrieved
 */
static uint64_t get_volume_size_from_mbr(volume_header_t* volume_header)
{
	uint64_t volume_size = 0;
	
	if(volume_header->nb_sectors_16b)
	{
		volume_size = (uint64_t)volume_header->sector_size
		                         * volume_header->nb_sectors_16b;
	}
	else if(volume_header->nb_sectors_32b)
	{
		volume_size = (uint64_t)volume_header->sector_size
		                         * volume_header->nb_sectors_32b;
	}
	else if(volume_header->nb_sectors_64b)
	{
		volume_size = (uint64_t)volume_header->sector_size
		                         * volume_header->nb_sectors_64b;
	}
	
	return volume_size;
}


/**
 * Compute the real volume's size.
 * 
 * @param io_data The structure holding major information for accessing the
 * volume
 * @return The volume size or 0 if it can't be determined
 */
static uint64_t get_volume_size(dis_iodata_t* io_data)
{
	uint64_t volume_size = 0;
	
	volume_size = get_volume_size_from_mbr(io_data->volume_header);
	
	if(!volume_size && io_data->metadata->version == V_SEVEN)
	{
		/*
		 * For version V_SEVEN, volumes can be partially encrypted.
		 * Therefore, try to get the real size from the NTFS data
		 */
		
		uint8_t* input = xmalloc(io_data->volume_header->sector_size);
		memset(input, 0, io_data->volume_header->sector_size);
		
		if(!read_decrypt_sectors(
			io_data,
			1,
			io_data->volume_header->sector_size,
			0,
			input))
		{
			xprintf(L_ERROR,
			       "Unable to read the NTFS header to get the volume's size\n");
			return 0;
		}
		
		volume_size = get_volume_size_from_mbr((volume_header_t*)input);
		
		xfree(input);
	}
	
	return volume_size;
}

