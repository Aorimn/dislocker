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

#include <errno.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dislocker/inouts/prepare.h"
#include "dislocker/inouts/sectors.h"
#include "dislocker/inouts/inouts.priv.h"

#include "dislocker/dislocker.priv.h"
#include "dislocker/return_values.h"


/**
 * Initialize data decryption keys
 *
 * @param dataset BitLocker dataset
 * @param fvek The entire 32 bytes FVEK, without the KEY structure
 * @param crypt Crypto structure to decrypt sectors
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int init_keys(bitlocker_dataset_t* dataset, datum_key_t* fvek_datum,
                     dis_crypt_t crypt)
{
	// Check parameters
	if(!dataset || !fvek_datum || !crypt)
		return DIS_RET_ERROR_DISLOCKER_INVAL;

	uint8_t* fvek    = NULL;
	size_t size_fvek = 0;

	if(!get_payload_safe(fvek_datum, (void**)&fvek, &size_fvek))
	{
		dis_printf(L_ERROR, "Can't get the FVEK datum payload. Abort.\n");
		return DIS_RET_ERROR_DISLOCKER_INVAL;
	}

	dis_printf(L_DEBUG,
	        "FVEK -----------------------------------------------------\n");
	hexdump(L_DEBUG, fvek, size_fvek);
	dis_printf(L_DEBUG,
	        "----------------------------------------------------------\n");

	/*
	 * It shouldn't be necessary as the algorithms should be the same, but
	 * still, we have a choice, so we do both
	 */
	uint16_t  algo[3] = {dataset->algorithm, fvek_datum->algo, 0};
	uint16_t* palgo   = algo;

	while(*palgo != 0)
	{
		if(dis_crypt_set_fvekey(crypt, *palgo, fvek) == DIS_RET_SUCCESS)
		{
			memclean(fvek, size_fvek);
			return DIS_RET_SUCCESS;
		}

		palgo++;
	}

	dis_printf(L_ERROR,
	        "Dataset's and FVEK's algorithms not supported: %#hx and %#hx\n",
	        dataset->algorithm, fvek_datum->algo);
	memclean(fvek, size_fvek);

	return DIS_RET_ERROR_CRYPTO_ALGORITHM_UNSUPPORTED;
}


/**
 * Get the readable size of the volume, starting at the partition's offset.
 *
 * @param dis_ctx The dislocker context used everywhere.
 * @return The number of readable bytes, or 0 if it couldn't be determined
 */
static uint64_t get_readable_size(dis_context_t dis_ctx)
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
		/* Block devices and the like: ask for the end of the volume */
		off_t cur = lseek(fd, 0, SEEK_CUR);

		size = lseek(fd, 0, SEEK_END);

		if(cur >= 0)
			lseek(fd, cur, SEEK_SET);
	}

	if(size <= 0 || size <= part_off)
		return 0;

	return (uint64_t)(size - part_off);
}


/**
 * Get the volume's size from the filesystem's VBR, which is found decrypted at
 * the beginning of the volume once the decryption keys are known.
 *
 * @param dis_ctx The dislocker context used everywhere.
 * @return The volume's size or 0 if it couldn't be determined
 */
static uint64_t get_volume_size_from_fs(dis_context_t dis_ctx)
{
	uint64_t volume_size = 0;
	void* old_vbr = NULL;
	uint16_t sector_size = dis_ctx->io_data.sector_size;
	uint8_t* vbr = NULL;

	if(sector_size == 0)
		return 0;

	vbr = dis_malloc(sector_size);
	memset(vbr, 0, sector_size);

	if(!read_decrypt_sectors(&dis_ctx->io_data, 1, sector_size, 0, vbr))
	{
		dis_printf(
			L_ERROR,
			"Unable to read the filesystem's VBR to get the volume's size\n"
		);
		dis_free(vbr);
		return 0;
	}

	old_vbr = dis_metadata_set_volume_header(dis_ctx->metadata, vbr);
	volume_size = dis_metadata_volume_size_from_vbr(dis_ctx->metadata);
	dis_metadata_set_volume_header(dis_ctx->metadata, old_vbr);

	/*
	 * NTFS doesn't count the backup boot sector, which sits at the very
	 * end of the volume, in its number of sectors. Only add it if it's a
	 * an NTFS filesystem 
	 */
	if(volume_size && memcmp(&vbr[3], "NTFS    ", 8) == 0)
		volume_size += sector_size;

	dis_free(vbr);

	return volume_size;
}


/**
 * Prepare a structure which hold data used for decryption/encryption
 *
 * @param dis_ctx The dislocker context used everywhere.
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int prepare_crypt(dis_context_t dis_ctx)
{
	dis_iodata_t* io_data;
	uint64_t readable_size = 0;
	uint64_t fs_volume_size = 0;

	if(!dis_ctx)
		return DIS_RET_ERROR_DISLOCKER_INVAL;

	io_data = &dis_ctx->io_data;
	io_data->metadata       = dis_ctx->metadata;
	io_data->part_off       = dis_ctx->cfg.offset;
	io_data->sector_size    = dis_inouts_sector_size(dis_ctx);
	io_data->decrypt_region = read_decrypt_sectors;
	io_data->encrypt_region = encrypt_write_sectors;
	io_data->encrypted_volume_size = dis_metadata_encrypted_volume_size(io_data->metadata);
	if (io_data->metadata->information->version == V_VISTA) {
		io_data->encrypted_volume_size = dis_metadata_volume_size_from_vbr(dis_ctx->metadata);
		io_data->encrypted_volume_size += io_data->sector_size;		//The volume size of Vista should include the DBR backup
	}
	io_data->backup_sectors_addr   = dis_metadata_ntfs_sectors_address(io_data->metadata);
	io_data->nb_backup_sectors     = dis_metadata_backup_sectors_count(io_data->metadata);

	/*
	 * Get volume size directly from dis_metadata_t, which is more accurate.
	 */
	io_data->volume_size = io_data->encrypted_volume_size;
	if(io_data->volume_size == 0 && !dis_metadata_is_decrypted_state(io_data->metadata))
	{
		dis_printf(L_ERROR, "Can't initialize the volume's size\n");
		return DIS_RET_ERROR_VOLUME_SIZE_NOT_FOUND;
	}

	/*
	 * The size found in the metadata may be bigger than the volume actually is, e. g. 
	 * when the volume was shrunk. Compare the metadata size to the actually readable size
	 * and if its larger, try to extract the size from the decrypted filesystem VBR.
	 */
	readable_size = get_readable_size(dis_ctx);
	if(readable_size != 0 && io_data->volume_size > readable_size)
	{
		dis_printf(
			L_WARNING,
			"Volume's size from the metadata (%1$#" PRIx64 " / %1$" PRIu64
			" bytes) is bigger than the readable size of the volume (%2$#"
			PRIx64 " / %2$" PRIu64 " bytes), the volume may have been shrunk "
			"after having been encrypted\n",
			io_data->volume_size,
			readable_size
		);

		fs_volume_size = get_volume_size_from_fs(dis_ctx);

		/*
		 * Fallback to the readable size if the filesystem VBR is also bigger.
		 */
		if(fs_volume_size != 0 && fs_volume_size <= readable_size)
			io_data->volume_size = fs_volume_size;
		else
			dis_printf(
				L_WARNING,
				"Volume's size from the decrypted filesystems VBR (%1$#" PRIx64 " / %1$" PRIu64
				" bytes) is bigger than the readable size of the volume (%2$#"
				PRIx64 " / %2$" PRIu64 " bytes), truncating to the readable size "
				"to prevent I/O errors\n",
				fs_volume_size,
				readable_size
			);

			io_data->volume_size = readable_size;
	}

	dis_printf(
		L_INFO,
		"Found volume's size: 0x%1$" PRIx64 " (%1$" PRIu64 ") bytes\n",
		io_data->volume_size
	);


	/*
	 * Don't initialize the mftmirror_backup field for it's the same as the
	 * backup_sectors_addr one.
	 */

	return DIS_RET_SUCCESS;
}
