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

#include <sys/stat.h>
#include <unistd.h>

#include "dislocker/inouts/sectors.h"
#include "dislocker/inouts/inouts.priv.h"
#include "dislocker/dislocker.priv.h"
#include "dislocker/config.priv.h"


/**
 * Getting the real volume size is proving to be quite difficult.
 */
static uint64_t get_volume_size(dis_context_t dis_ctx);
static uint64_t get_backing_store_size(dis_context_t dis_ctx);


/**
 * Get the volume's size and set it in the context. 
 * It's retrieved from the FVE volume's boot record or the NTFS volume's boot record.
 */
uint64_t dis_inouts_volume_size(dis_context_t dis_ctx)
{
	if(!dis_ctx)
		return 0;

	if(dis_ctx->io_data.volume_size)
		return dis_ctx->io_data.volume_size;

	dis_ctx->io_data.volume_size = get_volume_size(dis_ctx);

	return dis_ctx->io_data.volume_size;
}


/**
 * Compute the real volume's size. 
 *
 * @param dis_ctx The dislocker structure
 * @return The volume size or 0 if it can't be determined
 */
static uint64_t get_volume_size(dis_context_t dis_ctx)
{
	uint64_t volume_size  = 0;
	uint64_t backing_size = 0;
	void* old_vbr = NULL;
	uint16_t sector_size = dis_inouts_sector_size(dis_ctx);

	volume_size = dis_metadata_volume_size_from_vbr(dis_ctx->metadata);

	if(!volume_size &&
	    dis_metadata_information_version(dis_ctx->metadata) == V_SEVEN)
	{
		/*
		 * For version V_SEVEN, the FVE volume's boot record doesn't hold the
		 * number of sectors of the volume. The original one has been relocated
		 * though, so get the size from there.
		 */

		uint8_t* input = dis_malloc(sector_size);
		memset(input, 0, sector_size);

		if(!read_decrypt_sectors(&dis_ctx->io_data, 1, sector_size, 0, input))
		{
			dis_printf(L_ERROR,
			       "Unable to read the NTFS header to get the volume's size\n");
		}
		else
		{
			old_vbr = dis_metadata_set_volume_header(dis_ctx->metadata, input);
			volume_size = dis_metadata_volume_size_from_vbr(dis_ctx->metadata);
			dis_metadata_set_volume_header(dis_ctx->metadata, old_vbr);

			/*
			 * NTFS doesn't count the backup boot sector, which sits at the very
			 * end of the volume, in its number of sectors. Add it back, as the
			 * Vista code path above does, so the whole volume stays reachable.
			 */
			if(volume_size && memcmp(&input[3], "NTFS    ", 8) == 0)
				volume_size += sector_size;
		}

		dis_free(input);
	}

	if(!volume_size)
	{
		/*
		 * Last resort: the size recorded in the FVE metadata.
		 *
		 * This one describes the region covered by the encryption at the time
		 * it was written. Windows doesn't keep it in sync when the volume is
		 * resized afterwards, so it may be either bigger or smaller than the
		 * volume actually is. Only rely on it when nothing else is available.
		 */
		volume_size = dis_ctx->io_data.encrypted_volume_size;

		if(volume_size)
			dis_printf(
				L_WARNING,
				"Unable to compute the volume's size, falling back on the one "
				"found in the metadata, which may be inaccurate\n"
			);
	}

	/*
	 * Guard against advertising more than what can be read
	 */
	backing_size = get_backing_store_size(dis_ctx);
	if(volume_size && backing_size && volume_size > backing_size)
	{
		dis_printf(
			L_WARNING,
			"Computed volume's size (%1$#" PRIx64 " / %1$" PRIu64 " bytes) is "
			"bigger than the readable size of the volume (%2$#" PRIx64 " / %2$"
			PRIu64 " bytes), capping it\n",
			volume_size,
			backing_size
		);
		volume_size = backing_size;
	}

	dis_printf(
		L_INFO,
		"Found volume's size: 0x%1$" PRIx64 " (%1$" PRIu64 ") bytes\n",
		volume_size
	);

	return volume_size;
}


/**
 * Get the readable size of the volume's backing store, starting at the
 * partition's offset.
 *
 * @param dis_ctx The dislocker structure
 * @return The number of readable bytes, or 0 if it couldn't be determined
 */
static uint64_t get_backing_store_size(dis_context_t dis_ctx)
{
	struct stat st;
	off_t size     = 0;
	off_t part_off = dis_ctx->io_data.part_off;
	int   fd       = dis_ctx->io_data.volume_fd;

	if(fd < 0)
		return 0;

	if(fstat(fd, &st) == 0 && S_ISREG(st.st_mode))
	{
		size = st.st_size;
	}
	else
	{
		/* Block devices and the like: seek to the end of the volume */
		off_t cur = lseek(fd, 0, SEEK_CUR);

		size = lseek(fd, 0, SEEK_END);

		if(cur >= 0)
			lseek(fd, cur, SEEK_SET);
	}

	if(size <= 0 || size <= part_off)
		return 0;

	return (uint64_t)(size - part_off);
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
