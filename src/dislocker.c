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



#define _GNU_SOURCE

#include "accesses/accesses.h"


#include "sectors.h"
#include "metadata/datums.h"
#include "metadata/metadata.h"
#include "metadata/print_metadata.h"
#include "metadata/fvek.h"
#include "metadata/vmk.h"
#include "sectors.h"
#include "outputs/prepare.h"

#include "xstd/xstdio.h"

#include "config.h"
#include "dislocker.h"

#include <locale.h>


/*
 * On Darwin and FreeBSD, files are opened using 64 bits offsets/variables
 * and O_LARGEFILE isn't defined
 */
#if defined(__DARWIN) || defined(__FREEBSD)
#  define O_LARGEFILE 0
#endif /* __DARWIN || __FREEBSD */



int dis_initialize(dis_context_t* dis_ctx)
{
	void* bl_metadata = NULL;
	
	bitlocker_dataset_t* dataset = NULL;
	
	int ret = EXIT_SUCCESS;
	
	
	dis_ctx->io_data.enc_ctx = xmalloc(sizeof(contexts_t));
	memset(dis_ctx->io_data.enc_ctx, 0, sizeof(contexts_t));
	
	
	/* Initialize outputs */
	xstdio_init(dis_ctx->cfg.verbosity, dis_ctx->cfg.log_file);
	
	if(dis_ctx->cfg.verbosity >= L_DEBUG)
		dis_print_args(&dis_ctx->cfg);
	
	
	/*
	 * Check parameters given
	 */
	if(!dis_ctx->cfg.volume_path)
	{
		xprintf(L_CRITICAL, "No BitLocker volume path given. Abort.\n");
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	
	
	/* Open the volume as a (big) normal file */
	xprintf(L_DEBUG, "Trying to open '%s'...\n", dis_ctx->cfg.volume_path);
	dis_ctx->io_data.volume_fd = open(dis_ctx->cfg.volume_path, O_RDWR|O_LARGEFILE);
	if(dis_ctx->io_data.volume_fd < 0)
	{
		/* Trying to open it in read-only if O_RDWR doesn't work */
		dis_ctx->io_data.volume_fd = xopen(
			dis_ctx->cfg.volume_path,
			O_RDONLY|O_LARGEFILE
		);
		
		if(dis_ctx->io_data.volume_fd < 0)
		{
			xprintf(
				L_CRITICAL,
				"Failed to open %s: %s\n",
				dis_ctx->cfg.volume_path, strerror(errno)
			);
			dis_destroy(dis_ctx);
			return EXIT_FAILURE;
		}
		
		dis_ctx->cfg.is_ro |= READ_ONLY;
		xprintf(
			L_WARNING,
			"Failed to open %s for writing. Falling back to read-only.\n",
			dis_ctx->cfg.volume_path
		);
	}
	
	xprintf(L_DEBUG, "Opened (fd #%d).\n", dis_ctx->io_data.volume_fd);
	
	checkupdate_dis_state(dis_ctx, AFTER_OPEN_VOLUME);
	
	
	/* To print UTF-32 strings */
	setlocale(LC_ALL, "");
	
	
	
	/*
	 * Deal with the volume first
	 */
	xprintf(L_INFO, "Looking for BitLocker metadata...\n");
	
	/* Initialize structures */
	dis_ctx->io_data.volume_header = xmalloc(sizeof(volume_header_t));
	memset(dis_ctx->io_data.volume_header, 0, sizeof(volume_header_t));
	
	
	/* Getting volume infos */
	if(!get_volume_header(
		dis_ctx->io_data.volume_header,
		dis_ctx->io_data.volume_fd,
		dis_ctx->cfg.offset))
	{
		xprintf(
			L_CRITICAL,
			"Error during reading the volume: not enough byte read.\n"
		);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	/* For debug purpose, print the volume header retrieved */
	print_volume_header(L_DEBUG, dis_ctx->io_data.volume_header);
	
	checkupdate_dis_state(dis_ctx, AFTER_VOLUME_HEADER);
	
	
	/* Checking the signature */
	if(memcmp(BITLOCKER_SIGNATURE, dis_ctx->io_data.volume_header->signature,
	          BITLOCKER_SIGNATURE_SIZE) != 0)
	{
		xprintf(
			L_CRITICAL,
			"The signature of the volume (%.8s) doesn't match the "
			"BitLocker's one (-FVE-FS-). Abort.\n",
			dis_ctx->io_data.volume_header->signature
		);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	/* Checking sector size */
	if(dis_ctx->io_data.volume_header->sector_size == 0)
	{
		xprintf(L_CRITICAL, "The sector size found is null. Abort.\n");
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	/* Check if we're running under EOW mode */
	extern guid_t INFORMATION_OFFSET_GUID, EOW_INFORMATION_OFFSET_GUID;
	
	if(check_match_guid(dis_ctx->io_data.volume_header->guid, EOW_INFORMATION_OFFSET_GUID))
	{
		xprintf(L_INFO, "Volume has EOW_INFORMATION_OFFSET_GUID.\n");
		
		// First: get the EOW informations no matter what
		off_t source = (off_t)dis_ctx->io_data.volume_header->offset_eow_information[0];
		void* eow_infos = NULL;
		
		if(get_eow_information(source, &eow_infos, dis_ctx->io_data.volume_fd))
		{
			// Second: print them
			print_eow_infos(L_DEBUG, (bitlocker_eow_infos_t*)eow_infos);
			
			xfree(eow_infos);
			
			// Third: check if this struct passes checks
			if(get_eow_check_valid(dis_ctx->io_data.volume_header, dis_ctx->io_data.volume_fd, &eow_infos, &dis_ctx->cfg))
			{
				xprintf(L_INFO,
				        "EOW information at offset % " F_OFF_T
				        " passed the tests\n", source);
				xfree(eow_infos);
			}
			else
			{
				xprintf(L_ERROR,
				        "EOW information at offset % " F_OFF_T
				        " failed to pass the tests\n", source);
			}
		}
		else
		{
			xprintf(L_ERROR,
			        "Getting EOW information at offset % " F_OFF_T
			        " failed\n", source);
		}
		
		xprintf(L_CRITICAL, "EOW volume GUID not supported.\n");
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	else if(check_match_guid(dis_ctx->io_data.volume_header->guid, INFORMATION_OFFSET_GUID))
	{
		xprintf(L_INFO, "Volume GUID supported\n");
	}
	else
	{
		xprintf(L_CRITICAL, "Unknown volume GUID not supported.\n");
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	checkupdate_dis_state(dis_ctx, AFTER_VOLUME_CHECK);
	
	
	/* Getting BitLocker metadata and validate them */
	// TODO give the whole dis_ctx here for stopping at first INFORMATION (for stop_at)
	if(!get_metadata_check_validations(
		dis_ctx->io_data.volume_header,
		dis_ctx->io_data.volume_fd,
		&bl_metadata,
		&dis_ctx->cfg))
	{
		xprintf(
			L_CRITICAL,
			"A problem occured during the retrieving of metadata. Abort.\n"
		);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	if(dis_ctx->cfg.force_block == 0 || !bl_metadata)
	{
		xprintf(
			L_CRITICAL,
			"Can't find a valid set of metadata on the disk. Abort.\n"
		);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	/* Checking BitLocker version */
	if(((bitlocker_header_t*)bl_metadata)->version > V_SEVEN)
	{
		xprintf(
			L_CRITICAL,
			"Program designed only for BitLocker version 2 and less, "
			"the version here is %hd. Abort.\n",
			((bitlocker_header_t*)bl_metadata)->version
		);
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	xprintf(L_INFO, "BitLocker metadata found and parsed.\n");
	
	/* For debug purpose, print the metadata */
	print_bl_metadata(L_DEBUG, bl_metadata);
	print_data(L_DEBUG, bl_metadata);
	
	dis_ctx->io_data.metadata = bl_metadata;
	
	checkupdate_dis_state(dis_ctx, AFTER_BITLOCKER_INFORMATION_CHECK);
	
	
	/*
	 * If the state of the volume is currently decrypted, there's no key to grab
	 */
	if(((bitlocker_header_t*)bl_metadata)->curr_state == DECRYPTED)
		return EXIT_SUCCESS;
	
	
	/* Now that we have the metadata, get the dataset within it */
	if(get_dataset(bl_metadata, &dataset) != TRUE)
	{
		xprintf(L_CRITICAL, "Unable to find a valid dataset. Abort.\n");
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	/*
	 * Get the keys -- VMK & FVEK -- for dec/encryption operations
	 */
	if(dis_get_access(dis_ctx, dataset) == EXIT_FAILURE)
	{
		xprintf(L_CRITICAL, "Unable to grab VMK or FVEK. Abort.\n");
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	
	/*
	 * Init the decrypt keys' contexts
	 */
	if(!init_keys(dataset, dis_ctx->io_data.fvek, dis_ctx->io_data.enc_ctx))
	{
		xprintf(L_CRITICAL, "Can't initialize keys. Abort.\n");
		dis_destroy(dis_ctx);
		return EXIT_FAILURE;
	}
	
	
	/*
	 * Fill the dis_iodata_t structure which will be used for encryption &
	 * decryption afterward
	 */
	if(!prepare_crypt(dis_ctx))
	{
		xprintf(L_CRITICAL, "Can't prepare the crypt structure. Abort.\n");
		ret = EXIT_FAILURE;
	}
	
	
	// TODO add the BEFORE_DECRYPTION_CHECKING event here, so add the check here too
	
	
	/* Don't do the check for each and every enc/decryption operation */
	dis_ctx->io_data.volume_state = TRUE;
	
	if(dis_ctx->cfg.dont_check_state == FALSE &&
		!check_state(dis_ctx->io_data.metadata))
	{
		dis_ctx->io_data.volume_state = FALSE;
	}
	
	/* Clean everything before returning if there's an error */
	if(ret == EXIT_FAILURE)
		dis_destroy(dis_ctx);
	else
		dis_ctx->curr_state = COMPLETE_EVERYTHING;
	
	return ret;
}




int dislock(dis_context_t* dis_ctx, uint8_t* buffer, off_t offset, size_t size)
{
	uint8_t* buf = NULL;
	
	size_t sector_count;
	off_t  sector_start;
	size_t sector_to_add = 0;
	uint16_t sector_size = dis_ctx->io_data.sector_size;
	
	
	/* Check the state the BitLocker volume is in */
	if(dis_ctx->io_data.volume_state == FALSE)
	{
		xprintf(L_ERROR, "Invalid volume state, can't run safely. Abort.\n");
		return -EFAULT;
	}
	
	/* Check requested size */
	if(size == 0)
	{
		xprintf(L_DEBUG, "Received a request with a null size\n");
		return 0;
	}
	
	/* Check requested offset */
	if(offset < 0)
	{
		xprintf(L_ERROR, "Offset under 0: %#" F_OFF_T "\n", offset);
		return -EFAULT;
	}
	
	if(offset >= (off_t)dis_ctx->io_data.volume_size)
	{
		xprintf(
			L_ERROR,
			"Offset (%#" F_OFF_T ") exceeds volume's size (%#" F_OFF_T ")\n",
			offset,
			(off_t)dis_ctx->io_data.volume_size
		);
		return -EFAULT;
	}
	
	
	/* 
	 * The offset may not be at a sector limit, so we need to decrypt the entire
	 * sector where it starts. Idem for the end.
	 * 
	 * 
	 * Example:
	 * Sector number:              1   2   3   4   5   6   7...
	 * Data, continuous sectors: |___|___|___|___|___|___|__...
	 * The data the user want:         |__________|
	 * 
	 * The user don't want all of the data from sectors 2 and 5, but as the data
	 * are encrypted sector by sector, we have to decrypt them even though we
	 * won't give him the beginning of the sector 2 and the end of the sector 5.
	 * 
	 * 
	 * 
	 * Logic to do this is below :
	 *  - count the number of full sectors
	 *  - decode all sectors
	 *  - select and copy the data to user and deallocate all buffers
	 */
	
	/* Do not add sectors if we're at the edge of one already */
	if((offset % sector_size) != 0)
		sector_to_add += 1;
	if(((offset + (off_t)size) % sector_size) != 0)
		sector_to_add += 1;
	
	sector_count = ( size / sector_size ) + sector_to_add;
	sector_start = offset / sector_size;
	
	xprintf(L_DEBUG,
	        "--------------------{ Fuse reading }-----------------------\n");
	xprintf(L_DEBUG, "  Offset and size needed: %#" F_OFF_T
	                 " and %#" F_SIZE_T "\n", offset, size);
	xprintf(L_DEBUG, "  Start sector number: %#" F_OFF_T
	                 " || Number of sectors: %#" F_SIZE_T "\n",
	                 sector_start, sector_count);
	
	
	/*
	 * NOTE: DO NOT use xmalloc() here, we don't want to mess everything up!
	 * In general, do not use xfunctions() but xprintf() here.
	 */
	
	size_t to_allocate = size + sector_to_add*sector_size;
	xprintf(L_DEBUG, "  Trying to allocate %#" F_SIZE_T " bytes\n",to_allocate);
	buf = malloc(to_allocate);
	
	/* If buffer could not be allocated, return an error */
	if(!buf)
	{
		xprintf(L_ERROR, "Cannot allocate buffer for reading, abort.\n");
		xprintf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		if(errno < 0)
			return errno;
		else
			return -ENOMEM;
	}
	
	
	if(!dis_ctx->io_data.decrypt_region(
		&dis_ctx->io_data,
		sector_count,
		sector_size,
		sector_start * sector_size,
		buf))
	{
		free(buf);
		xprintf(L_ERROR, "Cannot decrypt sectors, abort.\n");
		xprintf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		return -EIO;
	}
	
	/* Now copy the required amount of data to the user buffer */
	memcpy(buffer, buf + (offset % sector_size), size);
	
	free(buf);
	
	xprintf(L_DEBUG, "  Outsize which will be returned: %d\n", (int)size);
	xprintf(L_DEBUG,
	        "-----------------------------------------------------------\n");
	
	return (int)size;
}




int enlock(dis_context_t* dis_ctx, uint8_t* buffer, off_t offset, size_t size)
{
	uint8_t* buf = NULL;
	int      ret = 0;
	
	uint16_t sector_size = dis_ctx->io_data.sector_size;
	size_t sector_count;
	off_t  sector_start;
	size_t sector_to_add = 0;
	
	
	/* Check the state the BitLocker volume is in */
	if(dis_ctx->io_data.volume_state == FALSE)
	{
		xprintf(L_ERROR, "Invalid volume state, can't run safely. Abort.\n");
		return -EFAULT;
	}
	
	/* Perform basic checks */
	if(dis_ctx->cfg.is_ro & READ_ONLY)
	{
		xprintf(L_DEBUG, "Only decrypting (-r or --read-only option passed)\n");
		return -EACCES;
	}
	
	if(size == 0)
	{
		xprintf(L_DEBUG, "Received a request with a null size\n");
		return 0;
	}
	
	if(offset < 0)
	{
		xprintf(L_ERROR, "Offset under 0: %#" F_OFF_T "\n", offset);
		return -EFAULT;
	}
	
	if(offset >= (off_t)dis_ctx->io_data.volume_size)
	{
		xprintf(L_ERROR, "Offset (%#" F_OFF_T ") exceeds volume's size (%#"
		                 F_OFF_T ")\n",
		        offset, (off_t)dis_ctx->io_data.volume_size);
		return -EFAULT;
	}
	
	if((size_t)offset + size >= (size_t)dis_ctx->io_data.volume_size)
	{
		size_t nsize = (size_t)dis_ctx->io_data.volume_size
		               - (size_t)offset;
		xprintf(
			L_WARNING,
			"Size modified as exceeding volume's end (offset=%#"
			F_SIZE_T " + size=%#" F_SIZE_T " >= volume_size=%#"
			F_SIZE_T ") ; new size: %#" F_SIZE_T "\n",
			(size_t)offset, size, (size_t)dis_ctx->io_data.volume_size, nsize
		);
		size = nsize;
	}
	
	
	/*
	 * Don't authorize to write on metadata, NTFS firsts sectors and on another
	 * area we shouldn't write to (don't know its signification yet).
	 */
	off_t metadata_offset = 0;
	off_t metadata_size   = 0;
	size_t virt_loop      = 0;
	
	for(virt_loop = 0; virt_loop < dis_ctx->io_data.nb_virt_region; virt_loop++)
	{
		metadata_size = (off_t)dis_ctx->io_data.virt_region[virt_loop].size;
		if(metadata_size == 0)
			continue;
		
		metadata_offset = (off_t)dis_ctx->io_data.virt_region[virt_loop].addr;
		
		if(offset >= metadata_offset &&
		   offset < metadata_offset + metadata_size)
		{
			xprintf(L_INFO, "Denying write request on the metadata (1:%#"
			        F_OFF_T ")\n", offset);
			return -EFAULT;
		}
		
		if(offset < metadata_offset &&
		   offset + (off_t)size > metadata_offset)
		{
			xprintf(L_INFO, "Denying write request on the metadata (2:%#"
			        F_OFF_T "+ %#" F_SIZE_T ")\n", offset, size);
			return -EFAULT;
		}
	}
	
	
	/*
	 * For BitLocker 7's volume, redirect writes to firsts sectors to the backed
	 * up ones
	 */
	if(dis_ctx->io_data.metadata->version == V_SEVEN &&
	   offset < dis_ctx->io_data.virtualized_size)
	{
		xprintf(L_DEBUG, "  Entering virtualized area\n");
		if(offset + (off_t)size <= dis_ctx->io_data.virtualized_size)
		{
			/*
			 * If all the request is within the virtualized area, just change
			 * the offset
			 */
			offset = offset + (off_t)dis_ctx->io_data.metadata->boot_sectors_backup;
			xprintf(L_DEBUG, "  `-> Just redirecting to %#"F_OFF_T"\n", offset);
		}
		else
		{
			/*
			 * But if the buffer is within the virtualized area and overflow it,
			 * split the request in two:
			 * - One for the virtualized area completely (which will be handled
			 *   by "recursing" and entering the case above)
			 * - One for the rest by changing the offset to the end of the
			 *   virtualized area and the size to the rest to be dec/encrypted
			 */
			xprintf(L_DEBUG, "  `-> Splitting the request in two, recursing\n");
			
			size_t nsize = (size_t)(dis_ctx->io_data.virtualized_size - offset);
			ret = enlock(dis_ctx, buffer, offset, nsize);
			if(ret < 0)
				return ret;
			
			offset  = dis_ctx->io_data.virtualized_size;
			size   -= nsize;
			buffer += nsize;
		}
	}
	
	
	/* 
	 * As in the read function, the offset may not be at a sector limit, so we
	 * need to decrypt the entire sector where it starts till the entire sector
	 * where it ends, then push the changes into the sectors at correct offset
	 * and finally encrypt all of these sectors and write them back to the disk.
	 * 
	 * 
	 * Example:
	 * Sector number:                    1   2   3   4   5   6   7...
	 * Data, continuous sectors:       |___|___|___|___|___|___|__...
	 * Where the user want to write:         |__________|
	 * 
	 * The user don't want to write everywhere, just from the middle of sector 2
	 * till a part of sector 5. But we're writing sectors by sectors to be able
	 * to encrypt using AES. So we'll need entire sectors 2 to 5 included.
	 * 
	 * 
	 * 
	 * Logic to do this is below :
	 *  - read and decrypt all sectors completely (2 to 5 in the example above)
	 *  - replace some data by the user's one
	 *  - encrypt and write the read sectors
	 */
	
	/* Do not add sectors if we're at the edge of one already */
	if((offset % sector_size) != 0)
		sector_to_add += 1;
	if(((offset + (off_t)size) % sector_size) != 0)
		sector_to_add += 1;
	
	
	sector_count = ( size / sector_size ) + sector_to_add;
	sector_start = offset / sector_size;
	
	xprintf(L_DEBUG,
	        "--------------------{ Fuse writing }-----------------------\n");
	xprintf(L_DEBUG, "  Offset and size requested: %#" F_OFF_T " and %#"
	        F_SIZE_T "\n", offset, size);
	xprintf(L_DEBUG, "  Start sector number: %#" F_OFF_T
	        " || Number of sectors: %#" F_SIZE_T "\n",
	        sector_start, sector_count);
	
	
	/*
	 * NOTE: DO NOT use xmalloc() here, we don't want to mess everything up!
	 * In general, do not use xfunctions() but xprintf() here.
	 */
	
	buf = malloc(size + sector_to_add * (size_t)sector_size);
	
	/* If buffer could not be allocated */
	if(!buf)
	{
		xprintf(L_ERROR, "Cannot allocate buffer for writing, abort.\n");
		xprintf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		return -ENOMEM;
	}
	
	
	if(!dis_ctx->io_data.decrypt_region(
		&dis_ctx->io_data,
		sector_count,
		sector_size,
		sector_start * sector_size,
		buf
	))
	{
		free(buf);
		xprintf(L_ERROR, "Cannot decrypt sectors, abort.\n");
		xprintf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		return -EIO;
	}
	
	
	/* Now copy the user's buffer to the received data */
	memcpy(buf + (offset % sector_size), buffer, size);
	
	
	/* Finally, encrypt the buffer and write it to the disk */
	if(!dis_ctx->io_data.encrypt_region(
		&dis_ctx->io_data,
		sector_count,
		sector_size,
		sector_start * sector_size,
		buf
	))
	{
		free(buf);
		xprintf(L_ERROR, "Cannot encrypt sectors, abort.\n");
		xprintf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		return -EIO;
	}
	
	
	free(buf);
	
	
	/* Note that ret is zero when no recursion occurs */
	int outsize = (int)size + ret;
	
	xprintf(L_DEBUG, "  Outsize which will be returned: %d\n", outsize);
	xprintf(L_DEBUG,
	        "-----------------------------------------------------------\n");
	
	return outsize;
}




int dis_destroy(dis_context_t* dis_ctx)
{
	/* Finish cleaning things */
	if(dis_ctx->io_data.metadata)
		xfree(dis_ctx->io_data.metadata);
	
	if(dis_ctx->io_data.volume_header)
		xfree(dis_ctx->io_data.volume_header);
	
	if(dis_ctx->io_data.vmk)
		xfree(dis_ctx->io_data.vmk);
	
	if(dis_ctx->io_data.fvek)
		xfree(dis_ctx->io_data.fvek);
	
	if(dis_ctx->io_data.enc_ctx)
		xfree(dis_ctx->io_data.enc_ctx);
	
	pthread_mutex_destroy(&dis_ctx->io_data.mutex_lseek_rw);
	
	dis_free_args(&dis_ctx->cfg);
	
	xclose(dis_ctx->io_data.volume_fd);
	
	xstdio_end();
	
	return EXIT_SUCCESS;
}
