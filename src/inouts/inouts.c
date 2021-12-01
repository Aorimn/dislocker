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

#include "dislocker/inouts/sectors.h"
#include "dislocker/inouts/inouts.priv.h"
#include "dislocker/dislocker.priv.h"
#include "dislocker/config.priv.h"


/**
 * Getting the real volume size is proving to be quite difficult.
 */
static uint64_t get_volume_size(dis_context_t dis_ctx);


/**
 * Get the volume's size. It's retrieved from the FVE volume's boot record or
 * the NTFS volume's boot record.
 */
uint64_t dis_inouts_volume_size(dis_context_t dis_ctx)
{
	if(!dis_ctx)
		return 0;

	if(dis_ctx->io_data.volume_size)
		return dis_ctx->io_data.volume_size;

	return get_volume_size(dis_ctx);
}


/**
 * Compute the real volume's size.
 *
 * @param dis_ctx The dislocker structure
 * @return The volume size or 0 if it can't be determined
 */
static uint64_t get_volume_size(dis_context_t dis_ctx)
{
	uint64_t volume_size = 0;
	void* old_vbr = NULL;
	uint16_t sector_size = dis_inouts_sector_size(dis_ctx);

	volume_size = dis_metadata_volume_size_from_vbr(dis_ctx->metadata);

	if(!volume_size &&
	    dis_metadata_information_version(dis_ctx->metadata) == V_SEVEN)
	{
		/*
		 * For version V_SEVEN, volumes can be partially encrypted.
		 * Therefore, try to get the real size from the NTFS data
		 */

		uint8_t* input = dis_malloc(sector_size);
		memset(input, 0, sector_size);

		if(!read_decrypt_sectors(&dis_ctx->io_data, 1, sector_size, 0, input))
		{
			dis_printf(L_ERROR,
			       "Unable to read the NTFS header to get the volume's size\n");
			return 0;
		}

		old_vbr = dis_metadata_set_volume_header(dis_ctx->metadata, input);
		volume_size = dis_metadata_volume_size_from_vbr(dis_ctx->metadata);
		dis_metadata_set_volume_header(dis_ctx->metadata, old_vbr);

		dis_free(input);
	}

	return volume_size;
}



uint16_t dis_inouts_sector_size(dis_context_t dis_ctx)
{
	if(!dis_ctx)
		return 0;

	if(dis_ctx->io_data.sector_size)
		return dis_ctx->io_data.sector_size;

	dis_ctx->io_data.sector_size = dis_metadata_sector_size(dis_ctx->metadata);

	return dis_ctx->io_data.sector_size;
}
