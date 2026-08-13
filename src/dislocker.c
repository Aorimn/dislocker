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



#define _GNU_SOURCE 1

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <limits.h>
#include <errno.h>
#include <pthread.h>

#include "dislocker/accesses/accesses.h"
#include "dislocker/accesses/rp/recovery_password.h"
#include "dislocker/metadata/datums.h"
#include "dislocker/metadata/metadata.h"
#include "dislocker/metadata/print_metadata.h"
#include "dislocker/metadata/fvek.h"
#include "dislocker/metadata/vmk.h"
#include "dislocker/inouts/prepare.h"
#include "dislocker/inouts/sectors.h"

#include "dislocker/xstd/xstdio.h"

#include "dislocker/return_values.h"
#include "dislocker/config.priv.h"
#include "dislocker/dislocker.priv.h"

#include <locale.h>

#ifndef __DIS_CORE_DUMPS
#include <sys/time.h>
#include <sys/resource.h>
#endif


/*
 * On Darwin and FreeBSD, files are opened using 64 bits offsets/variables
 * and O_LARGEFILE isn't defined
 */
#if defined(__DARWIN) || defined(__FREEBSD)
#  define O_LARGEFILE 0
#endif /* __DARWIN || __FREEBSD */



/* Get low-level errors the library encountered by looking at this variable */
int dis_errno;



dis_context_t dis_new()
{
	/* Allocate dislocker's context */
	dis_context_t dis_ctx = dis_malloc(sizeof(struct _dis_ctx));
	memset(dis_ctx, 0, sizeof(struct _dis_ctx));

#ifndef __DIS_CORE_DUMPS
	/* As we manage passwords and secrets, do not authorize core dumps */
	struct rlimit limit;
	limit.rlim_cur = 0;
	limit.rlim_max = 0;
	if (setrlimit(RLIMIT_CORE, &limit) != 0)
	{
		fprintf(stderr, "Cannot disable core dumps.\n");
		dis_free(dis_ctx);
		return NULL;
	}
#endif

	dis_ctx->fve_fd = -1;

	return dis_ctx;
}


int dis_initialize(dis_context_t dis_ctx)
{
	int ret = DIS_RET_SUCCESS;
	dis_metadata_config_t dis_meta_cfg = NULL;


	/* Initialize outputs */
	dis_stdio_init(dis_ctx->cfg.verbosity, dis_ctx->cfg.log_file);

	dis_printf(L_INFO, PROGNAME " by " AUTHOR ", v" VERSION " (compiled for " __OS "/" __ARCH ")\n");
#ifdef VERSION_DBG
	dis_printf(L_INFO, "Compiled version: " VERSION_DBG "\n");
#endif

	if(dis_ctx->cfg.verbosity >= L_DEBUG)
		dis_print_args(dis_ctx);


	/*
	 * Check parameters given
	 */
	if(!dis_ctx->cfg.volume_path)
	{
		dis_printf(L_CRITICAL, "No BitLocker volume path given. Abort.\n");
		dis_destroy(dis_ctx);
		return DIS_RET_ERROR_VOLUME_NOT_GIVEN;
	}



	/* Open the volume as a (big) normal file */
	dis_printf(L_DEBUG, "Trying to open '%s'...\n", dis_ctx->cfg.volume_path);
	dis_ctx->fve_fd = dis_open(dis_ctx->cfg.volume_path, O_RDWR|O_LARGEFILE);
	if(dis_ctx->fve_fd < 0)
	{
		/* Trying to open it in read-only if O_RDWR doesn't work */
		dis_ctx->fve_fd = dis_open(
			dis_ctx->cfg.volume_path,
			O_RDONLY|O_LARGEFILE
		);

		if(dis_ctx->fve_fd < 0)
		{
			dis_printf(
				L_CRITICAL,
				"Failed to open %s: %s\n",
				dis_ctx->cfg.volume_path, strerror(errno)
			);
			dis_destroy(dis_ctx);
			return DIS_RET_ERROR_FILE_OPEN;
		}

		dis_ctx->cfg.flags |= DIS_FLAG_READ_ONLY;
		dis_printf(
			L_WARNING,
			"Failed to open %s for writing. Falling back to read-only.\n",
			dis_ctx->cfg.volume_path
		);
	}

	dis_printf(L_DEBUG, "Opened (fd #%d).\n", dis_ctx->fve_fd);

	dis_ctx->io_data.volume_fd = dis_ctx->fve_fd;

	checkupdate_dis_state(dis_ctx, DIS_STATE_AFTER_OPEN_VOLUME);


	/* To print UTF-32 strings */
	setlocale(LC_ALL, "");

	/*
	 * The metadata configuration is freed when calling dis_metadata_destroy()
	 */
	dis_meta_cfg = dis_metadata_config_new();
	dis_meta_cfg->fve_fd       = dis_ctx->fve_fd;
	dis_meta_cfg->force_block  = dis_ctx->cfg.force_block;
	dis_meta_cfg->offset       = dis_ctx->cfg.offset;
	dis_meta_cfg->init_stop_at = dis_ctx->cfg.init_stop_at;

	dis_ctx->metadata = dis_metadata_new(dis_meta_cfg);
	if(dis_ctx->metadata == NULL)
	{
		dis_printf(L_CRITICAL, "Can't allocate metadata object. Abort.\n");
		dis_destroy(dis_ctx);
		return DIS_RET_ERROR_ALLOC;
	}

	dis_ctx->metadata->cfg->readonly = (dis_ctx->cfg.flags & DIS_FLAG_READ_ONLY) ? 1 : 0;

	ret = dis_metadata_initialize(dis_ctx->metadata);
	dis_ctx->curr_state = dis_meta_cfg->curr_state;
	if(ret != DIS_RET_SUCCESS)
	{
		/*
		 * If it's less than 0, then it's an error, if not, it's an early
		 * return of this function.
		 */
		if(ret < 0)
			dis_destroy(dis_ctx);
		return ret;
	}


	/*
	 * If the state of the volume is currently decrypted, there's no key to grab
	 */
	if(dis_ctx->metadata->information->curr_state != METADATA_STATE_DECRYPTED)
	{
		/*
		 * Get the keys -- VMK & FVEK -- for dec/encryption operations
		 */
		if((ret = dis_get_access(dis_ctx)) != DIS_RET_SUCCESS)
		{
			/*
			 * If it's less than 0, then it's an error, if not, it's an early
			 * return of this function.
			 */
			if(ret < 0)
			{
				dis_printf(L_CRITICAL, "Unable to grab VMK or FVEK. Abort.\n");
				dis_destroy(dis_ctx);
			}
			return ret;
		}

		/*
		 * Init the crypto structure
		 */
		dis_ctx->io_data.crypt = dis_crypt_new(
			dis_metadata_sector_size(dis_ctx->metadata),
			dis_ctx->metadata->dataset->algorithm
		);

		/*
		 * Init the decrypt keys' contexts
		 */
		if(init_keys(
			dis_metadata_set_dataset(dis_ctx->metadata, NULL),
			dis_ctx->io_data.fvek,
			dis_ctx->io_data.crypt) != DIS_RET_SUCCESS)
		{
			dis_printf(L_CRITICAL, "Can't initialize keys. Abort.\n");
			dis_destroy(dis_ctx);
			return DIS_RET_ERROR_CRYPTO_INIT;
		}
	}


	/*
	 * Fill the dis_iodata_t structure which will be used for encryption &
	 * decryption afterward
	 */
	if((ret = prepare_crypt(dis_ctx)) != DIS_RET_SUCCESS)
		dis_printf(L_CRITICAL, "Can't prepare the crypt structure. Abort.\n");


	// TODO add the DIS_STATE_BEFORE_DECRYPTION_CHECKING event here, so add the check here too


	/* Don't do the check for each and every enc/decryption operation */
	dis_ctx->io_data.volume_state = TRUE;

	int look_state = dis_ctx->cfg.flags & DIS_FLAG_DONT_CHECK_VOLUME_STATE;
	if(look_state == 0 &&
		!check_state(dis_ctx->metadata))
	{
		dis_ctx->io_data.volume_state = FALSE;
		ret = DIS_RET_ERROR_VOLUME_STATE_NOT_SAFE;
	}

	/* Clean everything before returning if there's an error */
	if(ret != DIS_RET_SUCCESS)
		dis_destroy(dis_ctx);
	else
		dis_ctx->curr_state = DIS_STATE_COMPLETE_EVERYTHING;

	return ret;
}




int dislock(dis_context_t dis_ctx, uint8_t* buffer, off_t offset, size_t size)
{
	uint8_t* buf = NULL;

	size_t sector_count;
	off_t  sector_start;
	size_t sector_to_add = 0;
	uint16_t sector_size;


	if(!dis_ctx || !buffer)
		return -EINVAL;


	/* Check the initialization's state */
	if(dis_ctx->curr_state != DIS_STATE_COMPLETE_EVERYTHING)
	{
		dis_printf(L_ERROR, "Initialization not completed. Abort.\n");
		return -EFAULT;
	}

	/* Check the state the BitLocker volume is in */
	if(dis_ctx->io_data.volume_state == FALSE)
	{
		dis_printf(L_ERROR, "Invalid volume state, can't run safely. Abort.\n");
		return -EFAULT;
	}

	/* Check requested size */
	if(size == 0)
	{
		dis_printf(L_DEBUG, "Received a request with a null size\n");
		return 0;
	}

	if(size > INT_MAX)
	{
		dis_printf(L_ERROR, "Received size which will overflow: %#" F_SIZE_T "\n",
			size
		);
		return -EOVERFLOW;
	}

	/* Check requested offset */
	if(offset < 0)
	{
		dis_printf(L_ERROR, "Offset under 0: %#" F_OFF_T "\n", offset);
		return -EFAULT;
	}

	if((offset >= (off_t)dis_ctx->io_data.volume_size) && !dis_metadata_is_decrypted_state(dis_ctx->io_data.metadata))
	{
		dis_printf(
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
	sector_size = dis_ctx->io_data.sector_size;
	if((offset % sector_size) != 0)
		sector_to_add += 1;
	if(((offset + (off_t)size) % sector_size) != 0)
		sector_to_add += 1;

	sector_count = ( size / sector_size ) + sector_to_add;
	sector_start = offset / sector_size;

	dis_printf(L_DEBUG,
	        "--------------------{ Fuse reading }-----------------------\n");
	dis_printf(L_DEBUG, "  Offset and size needed: %#" F_OFF_T
	                 " and %#" F_SIZE_T "\n", offset, size);
	dis_printf(L_DEBUG, "  Start sector number: %#" F_OFF_T
	                 " || Number of sectors: %#" F_SIZE_T "\n",
	                 sector_start, sector_count);


	/*
	 * NOTE: DO NOT use dis_malloc() here, we don't want to mess everything up!
	 * In general, do not use xfunctions() but dis_printf() here.
	 */

	size_t to_allocate = size + sector_to_add*sector_size;
	dis_printf(L_DEBUG, "  Trying to allocate %#" F_SIZE_T " bytes\n",to_allocate);
	buf = malloc(to_allocate);

	/* If buffer could not be allocated, return an error */
	if(!buf)
	{
		dis_printf(L_ERROR, "Cannot allocate buffer for reading, abort.\n");
		dis_printf(L_DEBUG,
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
		dis_printf(L_ERROR, "Cannot decrypt sectors, abort.\n");
		dis_printf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		return -EIO;
	}

	/* Now copy the required amount of data to the user buffer */
	memcpy(buffer, buf + (offset % sector_size), size);

	free(buf);

	dis_printf(L_DEBUG, "  Outsize which will be returned: %d\n", (int)size);
	dis_printf(L_DEBUG,
	        "-----------------------------------------------------------\n");

	return (int)size;
}




int enlock(dis_context_t dis_ctx, uint8_t* buffer, off_t offset, size_t size)
{
	uint8_t* buf = NULL;
	int      ret = 0;

	uint16_t sector_size;
	size_t sector_count;
	off_t  sector_start;
	size_t sector_to_add = 0;


	if(!dis_ctx || !buffer)
		return -EINVAL;

	/* Check the initialization's state */
	if(dis_ctx->curr_state != DIS_STATE_COMPLETE_EVERYTHING)
	{
		dis_printf(L_ERROR, "Initialization not completed. Abort.\n");
		return -EFAULT;
	}

	/* Check the state the BitLocker volume is in */
	if(dis_ctx->io_data.volume_state == FALSE)
	{
		dis_printf(L_ERROR, "Invalid volume state, can't run safely. Abort.\n");
		return -EFAULT;
	}

	/* Perform basic checks */
	if(dis_ctx->cfg.flags & DIS_FLAG_READ_ONLY)
	{
		dis_printf(L_DEBUG, "Only decrypting (-r or --read-only option passed)\n");
		return -EACCES;
	}

	if(size == 0)
	{
		dis_printf(L_DEBUG, "Received a request with a null size\n");
		return 0;
	}

	if(size > INT_MAX)
	{
		dis_printf(L_ERROR, "Received size which will overflow: %#" F_SIZE_T "\n",
			size
		);
		return -EOVERFLOW;
	}

	if(offset < 0)
	{
		dis_printf(L_ERROR, "Offset under 0: %#" F_OFF_T "\n", offset);
		return -EFAULT;
	}

	if(offset >= (off_t)dis_ctx->io_data.volume_size)
	{
		dis_printf(L_ERROR, "Offset (%#" F_OFF_T ") exceeds volume's size (%#"
		                 F_OFF_T ")\n",
		        offset, (off_t)dis_ctx->io_data.volume_size);
		return -EFAULT;
	}

	if(offset + (off_t)size >= (off_t)dis_ctx->io_data.volume_size)
	{
		size_t nsize = (size_t)dis_ctx->io_data.volume_size
		               - (size_t)offset;
		dis_printf(
			L_WARNING,
			"Size modified as exceeding volume's end (offset=%#"
			F_OFF_T " + size=%#" F_OFF_T " >= volume_size=%#"
			F_OFF_T ") ; new size: %#" F_SIZE_T "\n",
			offset, (off_t)size, dis_ctx->io_data.volume_size, nsize
		);
		size = nsize;
	}


	/*
	 * Don't authorize to write on metadata, NTFS firsts sectors and on another
	 * area we shouldn't write to (don't know its signification yet).
	 */
	if(dis_metadata_is_overwritten(dis_ctx->metadata, offset, size) != DIS_RET_SUCCESS)
		return -EFAULT;


	/*
	 * For BitLocker 7's volume, redirect writes to firsts sectors to the backed
	 * up ones
	 */
	if(dis_ctx->metadata->information->version == V_SEVEN &&
	   offset < dis_ctx->metadata->virtualized_size)
	{
		dis_printf(L_DEBUG, "  Entering virtualized area\n");
		if(offset + (off_t)size <= dis_ctx->metadata->virtualized_size)
		{
			/*
			 * If all the request is within the virtualized area, just change
			 * the offset
			 */
			offset = offset + (off_t)dis_ctx->metadata->information->boot_sectors_backup;
			dis_printf(L_DEBUG, "  `-> Just redirecting to %#"F_OFF_T"\n", offset);
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
			dis_printf(L_DEBUG, "  `-> Splitting the request in two, recursing\n");

			size_t nsize = (size_t)(dis_ctx->metadata->virtualized_size - offset);
			ret = enlock(dis_ctx, buffer, offset, nsize);
			if(ret < 0)
				return ret;

			offset  = dis_ctx->metadata->virtualized_size;
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
	sector_size = dis_ctx->io_data.sector_size;
	if((offset % sector_size) != 0)
		sector_to_add += 1;
	if(((offset + (off_t)size) % sector_size) != 0)
		sector_to_add += 1;


	sector_count = ( size / sector_size ) + sector_to_add;
	sector_start = offset / sector_size;

	dis_printf(L_DEBUG,
	        "--------------------{ Fuse writing }-----------------------\n");
	dis_printf(L_DEBUG, "  Offset and size requested: %#" F_OFF_T " and %#"
	        F_SIZE_T "\n", offset, size);
	dis_printf(L_DEBUG, "  Start sector number: %#" F_OFF_T
	        " || Number of sectors: %#" F_SIZE_T "\n",
	        sector_start, sector_count);


	/*
	 * NOTE: DO NOT use dis_malloc() here, we don't want to mess everything up!
	 * In general, do not use xfunctions() but dis_printf() here.
	 */

	buf = malloc(size + sector_to_add * (size_t)sector_size);

	/* If buffer could not be allocated */
	if(!buf)
	{
		dis_printf(L_ERROR, "Cannot allocate buffer for writing, abort.\n");
		dis_printf(L_DEBUG,
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
		dis_printf(L_ERROR, "Cannot decrypt sectors, abort.\n");
		dis_printf(L_DEBUG,
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
		dis_printf(L_ERROR, "Cannot encrypt sectors, abort.\n");
		dis_printf(L_DEBUG,
		       "-----------------------------------------------------------\n");
		return -EIO;
	}


	free(buf);


	/* Note that ret is zero when no recursion occurs */
	int outsize = (int)size + ret;

	dis_printf(L_DEBUG, "  Outsize which will be returned: %d\n", outsize);
	dis_printf(L_DEBUG,
	        "-----------------------------------------------------------\n");

	return outsize;
}



int dis_destroy(dis_context_t dis_ctx)
{
	/* Finish cleaning things */
	if(dis_ctx->io_data.vmk)
		dis_free(dis_ctx->io_data.vmk);

	if(dis_ctx->io_data.fvek)
		dis_free(dis_ctx->io_data.fvek);

	dis_crypt_destroy(dis_ctx->io_data.crypt);

	dis_metadata_destroy(dis_ctx->metadata);

	dis_free_args(dis_ctx);

	dis_close(dis_ctx->io_data.volume_fd);

	dis_stdio_end();

	dis_free(dis_ctx);

	return EXIT_SUCCESS;
}



int get_fvevol_fd(dis_context_t dis_ctx)
{
	return dis_ctx->fve_fd;
}


int dis_get_recovery_password(dis_context_t dis_ctx, char* password)
{
	if(!dis_ctx || !password)
		return DIS_RET_ERROR_DISLOCKER_INVAL;

	/* Check that we have a VMK */
	if(!dis_ctx->io_data.vmk)
	{
		dis_printf(L_ERROR, "No VMK available. Cannot extract recovery password.\n");
		return DIS_RET_ERROR_VMK_RETRIEVAL;
	}

	/* Extract VMK key from datum */
	uint8_t* vmk_key = (uint8_t*)dis_ctx->io_data.vmk + sizeof(datum_key_t);

	/* Call the extraction function */
	if(!extract_recovery_password_from_vmk(dis_ctx->metadata, vmk_key, password))
	{
		dis_printf(L_ERROR, "Failed to extract recovery password from VMK.\n");
		return DIS_RET_ERROR_RECOVERY_PASSWORD_EXTRACTION;
	}

	return DIS_RET_SUCCESS;
}



/**
 * This part below is for Ruby bindings
 */
#ifdef _HAVE_RUBY
#include <ruby.h>


VALUE dis_rb_classes[DIS_RB_CLASS_MAX];


static VALUE rb_init_dislocker(VALUE self, VALUE rb_vdis_ctx)
{
	rb_iv_set(self, "@context", rb_vdis_ctx);

	// TODO dis_initialize(dis_context_t* dis_ctx);

	return Qtrue;
}

static VALUE rb_dislock(VALUE self, VALUE rb_vbuffer, VALUE rb_voffset, VALUE rb_vsize)
{
	// TODO implement the function
	(void) self;
	(void) rb_vbuffer;
	(void) rb_voffset;
	(void) rb_vsize;
	return Qtrue;
}

static VALUE rb_enlock(VALUE self, VALUE rb_vbuffer, VALUE rb_voffset, VALUE rb_vsize)
{
	// TODO implement the function
	(void) self;
	(void) rb_vbuffer;
	(void) rb_voffset;
	(void) rb_vsize;
	return Qtrue;
}

static VALUE rb_destroy_dislocker(VALUE self)
{
	// TODO implement the function
	(void) self;
	return Qtrue;
}


void Init_libdislocker()
{
	VALUE rb_mDislocker = rb_define_module("Dislocker");
	dis_rb_classes[DIS_RB_CLASS_DISLOCKER] = rb_mDislocker;

	Init_metadata(rb_mDislocker);
	Init_accesses(rb_mDislocker);

	rb_define_method(rb_mDislocker, "initialize", rb_init_dislocker, 1);
	rb_define_method(rb_mDislocker, "dislock", rb_dislock, 3);
	rb_define_method(rb_mDislocker, "enlock", rb_enlock, 3);
	rb_define_method(rb_mDislocker, "destroy", rb_destroy_dislocker, 0);

	VALUE rb_mDisSignatures = rb_define_module_under(rb_mDislocker, "Signatures");
	VALUE signatures = rb_ary_new3(
		2,
		rb_str_new(BITLOCKER_SIGNATURE, BITLOCKER_SIGNATURE_SIZE),
		rb_str_new(BITLOCKER_TO_GO_SIGNATURE, BITLOCKER_TO_GO_SIGNATURE_SIZE)
	);
	rb_define_const(rb_mDisSignatures, "BitLocker", signatures);
}

#endif /* _HAVE_RUBY */
