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

#include <unistd.h>
#include <errno.h>

#include "dislocker/common.h"
#include "dislocker/return_values.h"
#include "dislocker/encryption/decrypt.h"
#include "dislocker/encryption/encrypt.h"
#include "dislocker/metadata/metadata.h"
#include "dislocker/inouts/inouts.priv.h"


/*
 * Number of thread you want to run for enc/decryption
 * NOTE: FUSE uses its own threads so the FUSE's functions can be called in
 * parallel. Use the environment variable FUSE_MAX_WORKERS to change the
 * FUSE's threads number.
 */
#define NB_THREAD 0
// Have a look at sysconf(_SC_NPROCESSORS_ONLN)
// Note: 512*NB_THREAD shouldn't be more than 2^16 (due to used types)


/* Struct we pass to a thread for buffer enc/decryption */
typedef struct _thread_arg
{
	size_t   nb_loop;
	uint16_t nb_threads;
	unsigned int thread_begin;

	uint16_t sector_size;
	off_t    sector_start;

	uint8_t* input;
	uint8_t* output;

	dis_iodata_t* io_data;
} thread_arg_t;



/** Prototype of functions used internally */
static void* thread_decrypt(void* args);
static void* thread_encrypt(void* args);
static void fix_read_sector_seven(
	dis_iodata_t* io_data,
	off_t sector_address,
	uint8_t *input,
	uint8_t *output
);
static void fix_read_sector_vista(
	dis_iodata_t* io_data,
	uint8_t* input,
	uint8_t *output
);
static void fix_write_sector_vista(
	dis_iodata_t* io_data,
	uint8_t* input,
	uint8_t *output
);




/**
 * Read and decrypt one or more sectors
 * @warning The sector_start has to be correctly aligned
 *
 * @param io_data The data structure containing volume's information
 * @param nb_read_sector The number of sectors to read
 * @param sector_size The size of one sector
 * @param sector_start The offset of the first sector to read; See the warning
 * above
 * @param output The output buffer where to put decrypted data
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int read_decrypt_sectors(
	dis_iodata_t* io_data,
	size_t nb_read_sector,
	uint16_t sector_size,
	off_t sector_start,
	uint8_t* output)
{
	// Check parameters
	if(!io_data || !output)
		return FALSE;


	size_t   nb_loop = 0;
	size_t   size    = nb_read_sector * sector_size;
	uint8_t* input   = malloc(size);
	off_t    off     = sector_start + io_data->part_off;

	memset(input , 0, size);
	memset(output, 0, size);

	/* Read the sectors we need */
	ssize_t read_size = pread(io_data->volume_fd, input, size, off);

	if(read_size <= 0)
	{
		free(input);
		dis_printf(
			L_ERROR,
			"Unable to read %#" F_SIZE_T " bytes from %#" F_OFF_T "\n",
			size,
			off
		);
		return FALSE;
	}


	/*
	 * We are assuming that we always have a "sector size" multiple disk length
	 * Can this assumption be wrong? I don't think so :)
	 */
	nb_loop = (size_t) read_size / sector_size;


	/* Run threads if compiled with */
#if NB_THREAD > 0
	{
		/* Threads preparations */
		pthread_t thread[NB_THREAD];
		thread_arg_t args[NB_THREAD];
		unsigned int loop = 0;

		for(loop = 0; loop < NB_THREAD; ++loop)
		{
			args[loop].nb_loop       = nb_loop;
			args[loop].nb_threads    = NB_THREAD;
			args[loop].thread_begin  = loop;
			args[loop].sector_size   = sector_size;
			args[loop].sector_start  = sector_start;
			args[loop].input         = input;
			args[loop].output        = output;

			args[loop].io_data       = io_data;

			pthread_create(
				&thread[loop],
				NULL,
				thread_decrypt,
				(void*) &args[loop]
			);
		}

		/* Wait for threads to end */
		for(loop = 0; loop < NB_THREAD; ++loop)
			pthread_join(thread[loop], NULL);
	}
#else
	{
		thread_arg_t arg;
		arg.nb_loop       = nb_loop;
		arg.nb_threads    = 1;
		arg.thread_begin  = 0;
		arg.sector_size   = sector_size;
		arg.sector_start  = sector_start;
		arg.input         = input;
		arg.output        = output;

		arg.io_data       = io_data;

		thread_decrypt(&arg);
	}
#endif


	free(input);

	return TRUE;
}


/**
 * Encrypt and write one or more sectors
 * @warning The sector_start has to be correctly aligned
 *
 * @param io_data The data structure containing volume's information
 * @param nb_write_sector The number of sectors to write
 * @param sector_size The size of one sector
 * @param sector_start The offset of the first sector to write; See the warning
 * above
 * @param output The input buffer which has to be encrypted and written
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int encrypt_write_sectors(
	dis_iodata_t* io_data,
	size_t nb_write_sector,
	uint16_t sector_size,
	off_t sector_start,
	uint8_t* input)
{
	// Check parameter
	if(!io_data || !input)
		return FALSE;

	uint8_t* output = malloc(nb_write_sector * sector_size);

	memset(output , 0, nb_write_sector * sector_size);

	/* Run threads if compiled with */
#if NB_THREAD > 0
	{
		/* Threads preparations */
		pthread_t thread[NB_THREAD];
		thread_arg_t args[NB_THREAD];
		unsigned int loop = 0;

		for(loop = 0; loop < NB_THREAD; ++loop)
		{
			args[loop].nb_loop       = nb_write_sector;
			args[loop].nb_threads    = NB_THREAD;
			args[loop].thread_begin  = loop;
			args[loop].sector_size   = sector_size;
			args[loop].sector_start  = sector_start;
			args[loop].input         = input;
			args[loop].output        = output;

			args[loop].io_data       = io_data;

			pthread_create(
				&thread[loop],
				NULL,
				thread_encrypt,
				(void*) &args[loop]
			);
		}

		/* Wait for threads to end */
		for(loop = 0; loop < NB_THREAD; ++loop)
			pthread_join(thread[loop], NULL);
	}
#else
	{
		thread_arg_t arg;
		arg.nb_loop       = nb_write_sector;
		arg.nb_threads    = 1;
		arg.thread_begin  = 0;
		arg.sector_size   = sector_size;
		arg.sector_start  = sector_start;
		arg.input         = input;
		arg.output        = output;

		arg.io_data       = io_data;

		thread_encrypt(&arg);
	}
#endif

	/* Write the sectors we want */
	ssize_t write_size = pwrite(
		io_data->volume_fd,
		output,
		nb_write_sector * sector_size,
		sector_start + io_data->part_off
	);

	free(output);
	if(write_size <= 0)
		return FALSE;

	return TRUE;
}


/**
 * Decrypt a sector region according to one or more thread
 *
 * @param params The structure used for thread parameters storage
 */
static void* thread_decrypt(void* params)
{
	if(!params)
		return NULL;

	thread_arg_t* args    = (thread_arg_t*) params;
	dis_iodata_t* io_data = args->io_data;

	off_t    loop         = args->thread_begin;
	uint16_t step_unit    = args->nb_threads;

	int      hover        = 0;
	uint16_t version      = dis_metadata_information_version(io_data->metadata);
	uint16_t sector_size  = args->sector_size;
	uint16_t step_size    = (uint16_t) (sector_size * step_unit);
	uint64_t encrypted_volume_total_sectors = io_data->encrypted_volume_size / sector_size;

	off_t    offset       = args->sector_start + sector_size * loop;
	uint8_t* loop_input   = args->input + sector_size * loop;
	uint8_t* loop_output  = args->output + sector_size * loop;


	for( ; loop < (off_t)args->nb_loop;
	       loop        += step_unit,
	       offset      += step_size,
	       loop_input  += step_size,
	       loop_output += step_size)
	{
		/*
		 * For BitLocker-encrypted volume with W$ 7/8:
		 *   - Don't decrypt the firsts sectors whatever might be the case, they
		 *   are saved elsewhere anyway.
		 * For these encrypted with W$ Vista:
		 *   - Change the first sector.
		 * For both of them:
		 *   - Zero out the metadata area returned to the user (not the one on
		 *   the disk, obviously).
		 *   - Don't decrypt sectors if we're outside the encrypted-volume's
		 *   size (but still in the volume's size obv). This is needed when the
		 *   encryption was paused during BitLocker's turn on.
		 */

		off_t sector_offset = args->sector_start / sector_size + loop;

		/* Check for zero out areas */
		hover = dis_metadata_is_overwritten(
			io_data->metadata,
			offset,
			sector_size);
		if(hover == DIS_RET_ERROR_METADATA_FILE_OVERWRITE)
		{
			memset(loop_output, 0, sector_size);
			continue;
		}


		/* Check for sectors fixing and non-encrypted sectors */
		if(version == V_SEVEN &&
		   (uint64_t)sector_offset < io_data->nb_backup_sectors)
		{
			/*
			 * The firsts sectors are encrypted in a different place on a
			 * Windows 7 volume
			 */
			fix_read_sector_seven(
				io_data,
				offset,
				loop_input,
				loop_output
			);
		}
		else if(version == V_SEVEN &&
		       (uint64_t)offset >= io_data->encrypted_volume_size)
		{
			/* Do not decrypt when there's nothing to */
			dis_printf(L_DEBUG,
				"  > Copying sector from 0x%" F_OFF_T
				" (%" F_SIZE_T " bytes)\n",
				offset, sector_size
			);
			memcpy(loop_output, loop_input, sector_size);
		}
		else if(version == V_VISTA && (sector_offset < 16 || sector_offset + 1 == encrypted_volume_total_sectors))
		{
			/*
			 * The firsts sectors are not really encrypted on a Vista volume
			 */
			if(sector_offset < 1 || sector_offset + 1 == encrypted_volume_total_sectors)
				fix_read_sector_vista(
					io_data,
					loop_input,
					loop_output
				);
			else
			{
				dis_printf(L_DEBUG,
					"  > Copying sector from 0x%" F_OFF_T
					" (%" F_SIZE_T " bytes)\n",
					offset, sector_size
				);
				memcpy(loop_output, loop_input, sector_size);
			}
		}
		else
		{
			/* Decrypt the sector */
			if(!decrypt_sector(
				io_data->crypt,
				loop_input,
				offset,
				loop_output
			))
				dis_printf(L_CRITICAL, "Decryption of sector %#" F_OFF_T
				                    " failed!\n", offset);
		}
	}

	return args->output;
}


/**
 * Encrypt a sector region according to one or more thread
 *
 * @param params The structure used for thread parameters storage
 */
static void* thread_encrypt(void* params)
{
	if(!params)
		return NULL;

	thread_arg_t* args    = (thread_arg_t*)params;
	dis_iodata_t* io_data = args->io_data;

	off_t    loop        = args->thread_begin;
	uint16_t step_unit   = args->nb_threads;

	uint16_t version     = dis_metadata_information_version(io_data->metadata);
	uint16_t sector_size = args->sector_size;
	uint16_t step_size   = (uint16_t) (sector_size * step_unit);
	uint64_t encrypted_volume_total_sectors = io_data->encrypted_volume_size / sector_size;

	uint8_t* loop_input  = args->input + sector_size * loop;
	uint8_t* loop_output = args->output + sector_size * loop;
	off_t    offset      = args->sector_start + sector_size * loop;


	for( ; loop < (off_t)args->nb_loop;
	       loop        += step_unit,
	       offset      += step_size,
	       loop_input  += step_size,
	       loop_output += step_size)
	{
		/*
		 * Just encrypt this sector
		 * Exception: don't encrypt it if the sector wasn't (as in the
		 * "BitLocker's-volume-encryption-was-paused case described in the
		 * decryption function above")
		 */

		off_t sector_offset = args->sector_start / sector_size + loop;

		/*
		 * NOTE: Seven specificities are dealt with earlier in the process
		 * see dislocker.c:enlock()
		 */
		if(version == V_VISTA && (sector_offset < 16 || sector_offset + 1 == encrypted_volume_total_sectors))
		{
			/*
			 * The firsts sectors are not really encrypted on a Vista volume
			 */
			if(sector_offset < 1 || sector_offset + 1 == encrypted_volume_total_sectors)
				fix_write_sector_vista(
					io_data,
					loop_input,
					loop_output
				);
			else
				memcpy(loop_output, loop_input, sector_size);
		}
		else if(version == V_SEVEN &&
		       (uint64_t)offset >= io_data->encrypted_volume_size)
		{
			memcpy(loop_output, loop_input, sector_size);
		}
		else
		{
			if(!encrypt_sector(
				io_data->crypt,
				loop_input,
				offset,
				loop_output
			))
				dis_printf(L_CRITICAL, "Encryption of sector %#" F_OFF_T
				                    " failed!\n", offset);
		}
	}

	return args->input;
}






/**
 * "Fix" the firsts sectors of a BitLocker volume encrypted with W$ Seven for
 * read operation
 *
 * @param io_data Data needed by the decryption to deal with encrypted data
 * @param sector_address Address of the sector to decrypt
 * @param output The buffer where to put fixed data
 */
static void fix_read_sector_seven(
	dis_iodata_t* io_data,
	off_t sector_address,
	uint8_t* input,
	uint8_t* output)
{
	// Check parameter
	if(!output)
		return;

	ssize_t read_size;

	/*
	 * NTFS's boot sectors are saved into the field "boot_sectors_backup" into
	 * metadata's header: the information structure. This field should have been
	 * reported into the "backup_sectors_addr" field of the dis_iodata_t
	 * structure.
	 * So we can use them here to give a good NTFS partition's beginning.
	 */
	off_t from = sector_address;
	off_t to   = from + (off_t)io_data->backup_sectors_addr;

	dis_printf(L_DEBUG, "  Fixing sector (7): from %#" F_OFF_T " to %#" F_OFF_T
	                 "\n", from, to);

	to += io_data->part_off;

	/* Read the real sector we need, at the offset we need it */
	read_size = pread(io_data->volume_fd, input, io_data->sector_size, to);

	if(read_size <= 0)
	{
		dis_printf(
			L_ERROR,
			"Unable to read %#" F_SIZE_T " bytes from %#" F_OFF_T "\n",
			io_data->sector_size,
			to
		);
		return;
	}

	to -= io_data->part_off;

	/* If the sector wasn't yet encrypted, don't decrypt it */
	if((uint64_t)to >= io_data->encrypted_volume_size)
	{
		memcpy(output, input, io_data->sector_size);
	}
	else
	{
		decrypt_sector(
			io_data->crypt,
			input,
			to,
			output
		);
	}
}


/**
 * "Fix" the firsts sectors of a BitLocker volume encrypted with W$ Vista for
 * read operation
 *
 * @param io_data Data needed by the decryption to deal with encrypted data
 * @param input The sector which needs a fix
 * @param output The buffer where to put fixed data
 */
static void fix_read_sector_vista(dis_iodata_t* io_data,
                                  uint8_t* input, uint8_t* output)
{
	// Check parameter
	if(!input || !output)
		return;

	/*
	 * Only two fields need to be changed: the NTFS signature and the MFT mirror
	 */
	memcpy(output, input, io_data->sector_size);

	dis_metadata_vista_vbr_fve2ntfs(io_data->metadata, output);
}


/**
 * "Fix" the firsts sectors of a BitLocker volume encrypted with W$ Vista for
 * write operation
 *
 * @param io_data Data needed by the decryption to deal with encrypted data
 * @param input The sector which needs a fix
 * @param output The buffer where to put fixed data
 */
static void fix_write_sector_vista(dis_iodata_t* io_data,
                                   uint8_t* input, uint8_t* output)
{
	// Check parameter
	if(!input || !output)
		return;

	/*
	 * Only two fields need to be changed: the NTFS signature and the MFT mirror
	 */
	memcpy(output, input, io_data->sector_size);

	dis_metadata_vista_vbr_ntfs2fve(io_data->metadata, output);
}
