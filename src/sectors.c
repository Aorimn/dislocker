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
static void fix_read_sector_seven(data_t* disk_op_data,
                                  off_t sector_address, uint8_t *output);
static void fix_read_sector_vista(data_t* disk_op_data, uint8_t* input,
                                  uint8_t *output);
static void fix_write_sector_vista(data_t* disk_op_data, uint8_t* input,
                                   uint8_t *output);




/**
 * Read and decrypt one or more sectors
 * @warning The sector_start has to be correctly aligned
 * 
 * @param fd The file descriptor to the volume
 * @param nb_read_sector The number of sectors to read
 * @param sector_size The size of one sector
 * @param sector_start The offset of the first sector to read; See the warning
 * above
 * @param output The output buffer where to put decrypted data
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int read_decrypt_sectors(int fd, size_t nb_read_sector, uint16_t sector_size,
                         off_t sector_start, uint8_t* output)
{
	// Check parameters
	if(!output)
		return FALSE;
	
	
	size_t   nb_loop = 0;
	uint8_t* input   = malloc(nb_read_sector * sector_size);
	
	memset(input , 0, nb_read_sector * sector_size);
	memset(output, 0, nb_read_sector * sector_size);
	
	
	/* Be sure to lock for lseek/read */
	if(pthread_mutex_lock(&disk_op_data.mutex_lseek_rw) != 0)
	{
		free(input);
		xprintf(L_ERROR, "Can't lock rw mutex: %s\n", strerror(errno));
		return FALSE;
	}
	
	
	/* Go where we need to read data */
	off_t off = sector_start + disk_op_data.part_off;
	if(lseek(fd, off, SEEK_SET) < 0)
	{
		free(input);
		xprintf(L_ERROR, "Unable to lseek to %#" F_OFF_T "\n", off);
		return FALSE;
	}
	
	/* Read the sectors we need */
	size_t size = nb_read_sector * sector_size;
	ssize_t read_size = read(fd, input, size);
	
	if(read_size <= 0)
	{
		free(input);
		xprintf(L_ERROR, "Unable to read %#" F_SIZE_T " bytes from %#" F_OFF_T
		                 "\n", size, off);
		return FALSE;
	}
	
	/* Unlock the previously locked mutex */
	if(pthread_mutex_unlock(&disk_op_data.mutex_lseek_rw) != 0)
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
 * @param fd The file descriptor to the volume
 * @param nb_write_sector The number of sectors to write
 * @param sector_size The size of one sector
 * @param sector_start The offset of the first sector to write; See the warning
 * above
 * @param output The input buffer which has to be encrypted and written
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int encrypt_write_sectors(int fd, size_t nb_write_sector, uint16_t sector_size,
                          off_t sector_start, uint8_t* input)
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
		
		thread_encrypt(&arg);
	}
#endif
	
	/* Be sure to lock for lseek/write */
	if(pthread_mutex_lock(&disk_op_data.mutex_lseek_rw) != 0)
	{
		free(output);
		xprintf(L_ERROR, "Can't lock rw mutex: %s\n", strerror(errno));
		return FALSE;
	}
	
	/* Go where we need to write data */
	off_t off = sector_start + disk_op_data.part_off;
	if(lseek(fd, off, SEEK_SET) < 0)
	{
		free(output);
		xprintf(L_ERROR, "Unable to lseek to %#" F_OFF_T "\n", off);
		return FALSE;
	}
	
	/* Write the sectors we want */
	ssize_t write_size = write(fd, output, nb_write_sector * sector_size);
	
	/* Unlock the previously locked mutex */
	if(pthread_mutex_unlock(&disk_op_data.mutex_lseek_rw) != 0)
	{
		free(output);
		xprintf(L_ERROR, "Can't unlock rw mutex: %s\n", strerror(errno));
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
	
	thread_arg_t* args = (thread_arg_t*)params;
	
	off_t loop               = 0;
	off_t offset             = args->sector_start;
	
	uint8_t* loop_input      = args->input;
	uint8_t* loop_output     = args->output;
	
	off_t    metadata_offset = 0;
	uint16_t version         = disk_op_data.metadata->version;
	
	
	off_t size = disk_op_data.metafiles_size;
	
	
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
		 * For BitLocker encrypted volume with W$ Seven:
		 *   Don't decrypt the firsts sectors whatever might be the case, they
		 *   are saved elsewhere anyway
		 * For these encrypted with W$ Vista:
		 *   Change the first sector
		 * For both of them:
		 *   Zero out the metadata area returned to the user (not the one on the
		 *   disk, obviously)
		 */
		
		off_t sector_offset = args->sector_start / args->sector_size + loop;
		
		/* Check for zero out areas */
		metadata_offset = (off_t)disk_op_data.metadata->offset_bl_header[0];
		if(offset >= metadata_offset &&
			offset <= metadata_offset + size)
		{
			memset(loop_output, 0, args->sector_size);
			continue;
		}
		
		metadata_offset = (off_t)disk_op_data.metadata->offset_bl_header[1];
		if(offset >= metadata_offset &&
			offset <= metadata_offset + size)
		{
			memset(loop_output, 0, args->sector_size);
			continue;
		}
		
		metadata_offset = (off_t)disk_op_data.metadata->offset_bl_header[2];
		if(offset >= metadata_offset &&
			offset <= metadata_offset + size)
		{
			memset(loop_output, 0, args->sector_size);
			continue;
		}
		
		if(version == V_SEVEN)
		{
			metadata_offset = (off_t)disk_op_data.metadata->boot_sectors_backup;
			if(offset >= metadata_offset &&
			   offset <= metadata_offset + disk_op_data.virtualized_size)
			{
				memset(loop_output, 0, args->sector_size);
				continue;
			}
		}
		
		
		/* Check for sectors fixing and non-encrypted sectors */
		if(version == V_SEVEN &&
		   (uint64_t)sector_offset < disk_op_data.metadata->nb_backup_sectors)
		{
			/*
			 * The firsts sectors are encrypted in a different place on a
			 * Windows 7 volume
			 */
			fix_read_sector_seven(
				&disk_op_data,
				offset,
				loop_output
			);
		}
		else if(version == V_VISTA && sector_offset < 16)
		{
			/*
			 * The firsts sectors are not really encrypted on a Vista volume
			 */
			if(sector_offset < 1)
				fix_read_sector_vista(
					&disk_op_data,
					 loop_input,
					 loop_output
				);
			else
				memcpy(loop_output, loop_input, args->sector_size);
		}
		else if((unsigned)offset >= disk_op_data.metadata->encrypted_volume_size)
		{
			memcpy(loop_output, loop_input, args->sector_size);
		}
		else
		{
			/* Decrypt the sector */
			if(!decrypt_sector(
				&disk_op_data,
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
	
	thread_arg_t* args = (thread_arg_t*)params;
	
	off_t   loop         = 0;
	off_t offset         = args->sector_start;
	
	uint8_t* loop_input  = args->input;
	uint8_t* loop_output = args->output;
	
	uint16_t version     = disk_op_data.metadata->version;
	
	
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
		 */
		
		off_t sector_offset = args->sector_start / args->sector_size + loop;
		
		/*
		 * NOTE: Seven specificities are dealt with earlier in the process
		 * see fuse.c:fs_write()
		 */
		if(version == V_VISTA && sector_offset < 16)
		{
			/*
			 * The firsts sectors are not really encrypted on a Vista volume
			 */
			if(sector_offset < 1)
				fix_write_sector_vista(
					&disk_op_data,
					 loop_input,
					 loop_output
				);
			else
				memcpy(loop_output, loop_input, args->sector_size);
		}
		else
		{
			if(!encrypt_sector(
				&disk_op_data,
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
 * @param disk_op_data Data needed by FUSE and the decryption to deal with
 * encrypted data
 * @param sector_address Address of the sector to decrypt
 * @param output The buffer where to put fixed data
 */
static void fix_read_sector_seven(data_t* disk_op_data,
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
	off_t to   = from + (off_t)disk_op_data->metadata->boot_sectors_backup;
	
	xprintf(L_DEBUG, "  Fixing sector (7): from %#" F_OFF_T " to %#" F_OFF_T
	                 "\n", from, to);
	
	to += disk_op_data->part_off;
	
	
	uint8_t* input = malloc(disk_op_data->sector_size);
	memset(input, 0, disk_op_data->sector_size);
	
	/* Be sure to lock for lseek/read */
	if(pthread_mutex_lock(&disk_op_data->mutex_lseek_rw) != 0)
	{
		free(input);
		xprintf(L_ERROR, "Can't lock rw mutex: %s\n", strerror(errno));
		return;
	}
	
	/* Go where we need to read the new sector */
	if(lseek(disk_op_data->volume_fd, to, SEEK_SET) <0)
	{
		free(input);
		xprintf(L_ERROR, "Unable to lseek to %#" F_OFF_T "\n", to);
		return;
	}
	
	/* Read the real sector we need */
	ssize_t read_size = read(disk_op_data->volume_fd, input,
	                         disk_op_data->sector_size);
	
	
	/* Unlock the previously locked mutex */
	if(pthread_mutex_unlock(&disk_op_data->mutex_lseek_rw) != 0)
	{
		free(input);
		xprintf(L_ERROR, "Can't unlock rw mutex: %s\n", strerror(errno));
		return;
	}
	
	
	if(read_size <= 0)
	{
		free(input);
		xprintf(L_ERROR, "Unable to read %#" F_SIZE_T " bytes from %#" F_OFF_T
		                 "\n", disk_op_data->sector_size, to);
		return;
	}
	
	
	to -= disk_op_data->part_off;
	decrypt_sector(
		disk_op_data,
		input,
		to,
		output
	);
	
	
	free(input);
}


/**
 * "Fix" the firsts sectors of a BitLocker volume encrypted with W$ Vista for
 * read operation
 * 
 * @param disk_op_data Data needed by FUSE and the decryption to deal with
 * encrypted data
 * @param input The sector which needs a fix
 * @param output The buffer where to put fixed data
 */
static void fix_read_sector_vista(data_t* disk_op_data,
                                  uint8_t* input, uint8_t *output)
{ 
	// Check parameter
	if(!input || !output)
		return;
	
	xprintf(L_DEBUG, "  Fixing sector (Vista): replacing signature "
	                 "and MFTMirror field by: %#llx\n",
	                 disk_op_data->metadata->boot_sectors_backup);
	
	/* 
	 * Only two fields need to be changed: the NTFS signature and the MFT mirror
	 */
	memcpy(output, input, disk_op_data->sector_size);
	
	volume_header_t* formatted_output = (volume_header_t*)output;
	
	/* This is for the NTFS signature */
	memcpy(formatted_output->signature, NTFS_SIGNATURE, NTFS_SIGNATURE_SIZE);
	
	/* And this is for the MFT Mirror field */
	formatted_output->mft_mirror = disk_op_data->metadata->boot_sectors_backup;
}


/**
 * "Fix" the firsts sectors of a BitLocker volume encrypted with W$ Vista for
 * write operation
 * 
 * @param disk_op_data Data needed by FUSE and the decryption to deal with
 * encrypted data
 * @param input The sector which needs a fix
 * @param output The buffer where to put fixed data
 */
static void fix_write_sector_vista(data_t* disk_op_data,
                                   uint8_t* input, uint8_t *output)
{ 
	// Check parameter
	if(!input || !output)
		return;
	
	/* 
	 * Only two fields need to be changed: the NTFS signature and the MFT mirror
	 */
	memcpy(output, input, disk_op_data->sector_size);
	
	volume_header_t* formatted_output = (volume_header_t*)output;
	
	/* This is for the BitLocker signature */
	memcpy(formatted_output->signature,
	       BITLOCKER_SIGNATURE, BITLOCKER_SIGNATURE_SIZE);
	
	/* And this is for the metadata LCN */
	formatted_output->metadata_lcn =
		disk_op_data->metadata->offset_bl_header[0] /
		(uint64_t)(
			formatted_output->sectors_per_cluster *
			formatted_output->sector_size
		);
	
	xprintf(L_DEBUG, "  Fixing sector (Vista): replacing signature "
	                 "and MFTMirror field by: %#llx\n",
	                 formatted_output->metadata_lcn);
	
}

