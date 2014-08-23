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


#include "common.h"
#include "encryption/decrypt.h"
#include "encryption/encrypt.h"
#include "metadata/metadata.h"
#include "sectors.h"



/** Prototype of functions used internally */
static void* thread_decrypt(void* args);
static void* thread_encrypt(void* args);
static void fix_read_sector_seven(
	dis_iodata_t* io_data,
	off_t sector_address,
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
	if(!output)
		return FALSE;
	
	
	size_t   nb_loop = 0;
	size_t   size    = nb_read_sector * sector_size;
	uint8_t* input   = malloc(size);
	
	memset(input , 0, size);
	memset(output, 0, size);
	
	
	/* Be sure to lock for lseek/read */
	if(pthread_mutex_lock(&io_data->mutex_lseek_rw) != 0)
	{
		free(input);
		xprintf(L_ERROR, "Can't lock rw mutex: %s\n", strerror(errno));
		return FALSE;
	}
	
	
	/* Go where we need to read data */
	off_t off = sector_start + io_data->part_off;
	if(lseek(io_data->volume_fd, off, SEEK_SET) < 0)
	{
		free(input);
		xprintf(L_ERROR, "Unable to lseek to %#" F_OFF_T "\n", off);
		return FALSE;
	}
	
	/* Read the sectors we need */
	ssize_t read_size = read(io_data->volume_fd, input, size);
	
	if(read_size <= 0)
	{
		free(input);
		xprintf(L_ERROR, "Unable to read %#" F_SIZE_T " bytes from %#" F_OFF_T
		                 "\n", size, off);
		return FALSE;
	}
	
	/* Unlock the previously locked mutex */
	if(pthread_mutex_unlock(&io_data->mutex_lseek_rw) != 0)
	{
		free(input);
		xprintf(L_ERROR, "Can't unlock rw mutex: %s\n", strerror(errno));
		return FALSE;
	}
	
	
	/*
	 * We are assuming that we always have a "sector size" multiple disk length
	 * Can this assumption be wrong? I don't think so :)
	 */
	nb_loop = (size_t)read_size / sector_size;
	
	
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
			args[loop].sector_size   = sector_size;
			args[loop].sector_start  = sector_start;
			args[loop].input         = input;
			args[loop].output        = output;
			
			args[loop].modulo        = NB_THREAD;
			args[loop].modulo_result = loop;
			
			args[loop].io_data       = io_data;
			
			pthread_create( &thread[loop], NULL,
			                thread_decrypt, (void*) &args[loop] );
		}
		
		/* Wait for threads to end */
		for(loop = 0; loop < NB_THREAD; ++loop)
			pthread_join(thread[loop], NULL);
	}
#else
	{
		thread_arg_t arg;
		arg.nb_loop       = nb_loop;
		arg.sector_size   = sector_size;
		arg.sector_start  = sector_start;
		arg.input         = input;
		arg.output        = output;
		
		arg.modulo        = 0;
		arg.modulo_result = 42;
		
		args.io_data      = io_data;
		
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
	if(!input)
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
			args[loop].sector_size   = sector_size;
			args[loop].sector_start  = sector_start;
			args[loop].input         = input;
			args[loop].output        = output;
			
			args[loop].modulo        = NB_THREAD;
			args[loop].modulo_result = loop;
			
			args[loop].io_data       = io_data;
			
			pthread_create( &thread[loop], NULL,
			                thread_encrypt, (void*) &args[loop] );
		}
		
		/* Wait for threads to end */
		for(loop = 0; loop < NB_THREAD; ++loop)
			pthread_join(thread[loop], NULL);
	}
#else
	{
		thread_arg_t arg;
		arg.nb_loop       = nb_loop;
		arg.sector_size   = sector_size;
		arg.sector_start  = sector_start;
		arg.input         = input;
		arg.output        = output;
		
		arg.modulo        = 0;
		arg.modulo_result = 42;
		
		args.io_data      = io_data;
		
		thread_encrypt(&arg);
	}
#endif
	
	/* Be sure to lock for lseek/write */
	if(pthread_mutex_lock(&io_data->mutex_lseek_rw) != 0)
	{
		free(output);
		xprintf(L_ERROR, "Can't lock rw mutex: %s\n", strerror(errno));
		return FALSE;
	}
	
	/* Go where we need to write data */
	off_t off = sector_start + io_data->part_off;
	if(lseek(io_data->volume_fd, off, SEEK_SET) < 0)
	{
		free(output);
		xprintf(L_ERROR, "Unable to lseek to %#" F_OFF_T "\n", off);
		return FALSE;
	}
	
	/* Write the sectors we want */
	ssize_t write_size = write(
		io_data->volume_fd,
		output,
		nb_write_sector * sector_size
	);
	
	/* Unlock the previously locked mutex */
	if(pthread_mutex_unlock(&io_data->mutex_lseek_rw) != 0)
	{
		xprintf(L_ERROR, "Can't unlock rw mutex: %s\n", strerror(errno));
		free(output);
		return FALSE;
	}
	
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
	
	thread_arg_t* args    = (thread_arg_t*)params;
	dis_iodata_t* io_data = args->io_data;
	
	off_t loop               = 0;
	off_t offset             = args->sector_start;
	
	uint8_t* loop_input      = args->input;
	uint8_t* loop_output     = args->output;
	
	size_t   virt_loop       = 0;
	off_t    metadata_offset = 0;
	uint16_t version         = io_data->metadata->version;
	
	off_t size               = 0;
	
	
	// TODO see to be more intelligent on these loops
	for(loop = 0; loop < (off_t)args->nb_loop; ++loop,
	                               offset      += args->sector_size,
	                               loop_input  += args->sector_size,
	                               loop_output += args->sector_size)
	{
		if(args->modulo != 0 && args->modulo != 1
			&& (loop % args->modulo) == args->modulo_result)
			continue;
		
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
		
		off_t sector_offset = args->sector_start / args->sector_size + loop;
		
		/* Check for zero out areas */
		for(virt_loop = 0; virt_loop < io_data->nb_virt_region; virt_loop++)
		{
			size = (off_t)io_data->virt_region[virt_loop].size;
			if(size == 0)
				continue;
			
			metadata_offset = (off_t)io_data->virt_region[virt_loop].addr;
			if(offset >= metadata_offset &&
				offset <= metadata_offset + size)
			{
				xprintf(L_DEBUG,
					"  > Zeroing sector from 0x%" F_OFF_T
					" (%" F_SIZE_T " bytes)\n",
					offset, args->sector_size
				);
				memset(loop_output, 0, args->sector_size);
				break;
			}
		}
		
		/*
		 * If we've broke from the previous loop, that means we have to continue
		 */
		if(virt_loop != io_data->nb_virt_region)
			continue;
		
		
		/* Check for sectors fixing and non-encrypted sectors */
		if(version == V_SEVEN &&
		   (uint64_t)sector_offset < io_data->metadata->nb_backup_sectors)
		{
			/*
			 * The firsts sectors are encrypted in a different place on a
			 * Windows 7 volume
			 */
			fix_read_sector_seven(
				io_data,
				offset,
				loop_output
			);
		}
		else if(version == V_SEVEN &&
		       (uint64_t)offset >= io_data->metadata->encrypted_volume_size)
		{
			/* Do not decrypt when there's nothing to */
			xprintf(L_DEBUG,
				"  > Copying sector from 0x%" F_OFF_T
				" (%" F_SIZE_T " bytes)\n",
				offset, args->sector_size
			);
			memcpy(loop_output, loop_input, args->sector_size);
		}
		else if(version == V_VISTA && sector_offset < 16)
		{
			/*
			 * The firsts sectors are not really encrypted on a Vista volume
			 */
			if(sector_offset < 1)
				fix_read_sector_vista(
					io_data,
					loop_input,
					loop_output
				);
			else
			{
				xprintf(L_DEBUG,
					"  > Copying sector from 0x%" F_OFF_T
					" (%" F_SIZE_T " bytes)\n",
					offset, args->sector_size
				);
				memcpy(loop_output, loop_input, args->sector_size);
			}
		}
		else
		{
			/* Decrypt the sector */
			if(!decrypt_sector(
				io_data,
				loop_input,
				offset,
				loop_output
			))
				xprintf(L_CRITICAL, "Decryption of sector %#" F_OFF_T
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
	
	off_t   loop         = 0;
	off_t offset         = args->sector_start;
	
	uint8_t* loop_input  = args->input;
	uint8_t* loop_output = args->output;
	
	uint16_t version     = io_data->metadata->version;
	
	
	for(loop = 0; loop < (off_t)args->nb_loop; ++loop,
	                               offset      += args->sector_size,
	                               loop_input  += args->sector_size,
	                               loop_output += args->sector_size)
	{
		if(args->modulo != 0 && args->modulo != 1
			&& (loop % args->modulo) == args->modulo_result)
			continue;
		
		/*
		 * Just encrypt this sector
		 * Exception: don't encrypt it if the sector wasn't (as in the
		 * "BitLocker's-volume-encryption-was-paused case decribed in the
		 * decryption function above")
		 */
		
		off_t sector_offset = args->sector_start / args->sector_size + loop;
		
		/*
		 * NOTE: Seven specificities are dealt with earlier in the process
		 * see dislocker.c:enlock()
		 */
		if(version == V_VISTA && sector_offset < 16)
		{
			/*
			 * The firsts sectors are not really encrypted on a Vista volume
			 */
			if(sector_offset < 1)
				fix_write_sector_vista(
					io_data,
					loop_input,
					loop_output
				);
			else
				memcpy(loop_output, loop_input, args->sector_size);
		}
		else if(version == V_SEVEN &&
		       (uint64_t)offset >= io_data->metadata->encrypted_volume_size)
		{
			memcpy(loop_output, loop_input, args->sector_size);
		}
		else
		{
			if(!encrypt_sector(
				io_data,
				loop_input,
				offset,
				loop_output
			))
				xprintf(L_CRITICAL, "Encryption of sector %#" F_OFF_T
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
static void fix_read_sector_seven(dis_iodata_t* io_data,
                                  off_t sector_address, uint8_t *output)
{ 
	// Check parameter
	if(!output)
		return;
	
	/* 
	 * NTFS's boot sectors are saved into the field "boot_sectors_backup" into
	 * metadata.
	 * So we can use them here to give a good NTFS partition's beginning.
	 */
	off_t from = sector_address;
	off_t to   = from + (off_t)io_data->metadata->boot_sectors_backup;
	
	xprintf(L_DEBUG, "  Fixing sector (7): from %#" F_OFF_T " to %#" F_OFF_T
	                 "\n", from, to);
	
	to += io_data->part_off;
	
	
	uint8_t* input = malloc(io_data->sector_size);
	memset(input, 0, io_data->sector_size);
	
	/* Be sure to lock for lseek/read */
	if(pthread_mutex_lock(&io_data->mutex_lseek_rw) != 0)
	{
		free(input);
		xprintf(L_ERROR, "Can't lock rw mutex: %s\n", strerror(errno));
		return;
	}
	
	/* Go where we need to read the new sector */
	if(lseek(io_data->volume_fd, to, SEEK_SET) <0)
	{
		free(input);
		xprintf(L_ERROR, "Unable to lseek to %#" F_OFF_T "\n", to);
		return;
	}
	
	/* Read the real sector we need */
	ssize_t read_size = read(io_data->volume_fd, input, io_data->sector_size);
	
	
	/* Unlock the previously locked mutex */
	if(pthread_mutex_unlock(&io_data->mutex_lseek_rw) != 0)
	{
		free(input);
		xprintf(L_ERROR, "Can't unlock rw mutex: %s\n", strerror(errno));
		return;
	}
	
	
	if(read_size <= 0)
	{
		free(input);
		xprintf(L_ERROR, "Unable to read %#" F_SIZE_T " bytes from %#" F_OFF_T
		                 "\n", io_data->sector_size, to);
		return;
	}
	
	to -= io_data->part_off;
	
	/* If the sector wasn't yet encrypted, don't decrypt it */
	if((uint64_t)to >= io_data->metadata->encrypted_volume_size)
	{
		memcpy(output, input, io_data->sector_size);
	}
	else
	{
		decrypt_sector(
			io_data,
			input,
			to,
			output
		);
	}
	
	free(input);
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
                                  uint8_t* input, uint8_t *output)
{ 
	// Check parameter
	if(!input || !output)
		return;
	
	xprintf(L_DEBUG, "  Fixing sector (Vista): replacing signature "
	                 "and MFTMirror field by: %#llx\n",
	                 io_data->metadata->mftmirror_backup);
	
	/* 
	 * Only two fields need to be changed: the NTFS signature and the MFT mirror
	 */
	memcpy(output, input, io_data->sector_size);
	
	volume_header_t* formatted_output = (volume_header_t*)output;
	
	/* This is for the NTFS signature */
	memcpy(formatted_output->signature, NTFS_SIGNATURE, NTFS_SIGNATURE_SIZE);
	
	/* And this is for the MFT Mirror field */
	formatted_output->mft_mirror = io_data->metadata->mftmirror_backup;
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
                                   uint8_t* input, uint8_t *output)
{ 
	// Check parameter
	if(!input || !output)
		return;
	
	/* 
	 * Only two fields need to be changed: the NTFS signature and the MFT mirror
	 */
	memcpy(output, input, io_data->sector_size);
	
	volume_header_t* formatted_output = (volume_header_t*)output;
	
	/* This is for the BitLocker signature */
	memcpy(formatted_output->signature,
	       BITLOCKER_SIGNATURE, BITLOCKER_SIGNATURE_SIZE);
	
	/* And this is for the metadata LCN */
	formatted_output->metadata_lcn =
		io_data->metadata->offset_bl_header[0] /
		(uint64_t)(
			formatted_output->sectors_per_cluster *
			formatted_output->sector_size
		);
	
	xprintf(
		L_DEBUG,
		"  Fixing sector (Vista): replacing signature "
		"and MFTMirror field by: %#llx\n",
		formatted_output->metadata_lcn
	);
}

