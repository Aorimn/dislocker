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

#include "encryption/crc32.h"
#include "metadata.h"
#include "print_metadata.h"


/**
 * Read the beginning of a volume and put it in a volume_header_t structure
 * 
 * @param volume_header A volume header structure to complete
 * @param fd A file descriptor to the volume
 * @param offset The initial partition offset
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_volume_header(volume_header_t *volume_header, int fd, off_t offset)
{
	if(!volume_header || fd < 0)
		return FALSE;
	
	// Go to the beginning
	xlseek(fd, offset, SEEK_SET);
	
	xprintf(L_INFO, "Reading volume header...\n");
	
	// Read and place data into the volume_header_t structure
	ssize_t nb_read = xread(fd, volume_header, sizeof(volume_header_t));
	
	// Check if we read all we wanted
	if(nb_read != sizeof(volume_header_t))
		return FALSE;
	
	xprintf(L_INFO, "Volume header read\n");
	
	return TRUE;
}


/**
 * Read one of BitLocker metadata and put data in a bitlocker_header_t structure
 * This also take the dataset header as it's in the bitlocker_header_t
 * Then read all metadata, including datums
 * 
 * @param source The beginning address of the header
 * @param metadata One of the BitLocker metadata, beginning at source
 * @param fd A file descriptor to the volume
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_metadata(off_t source, void **metadata, int fd)
{
	if(!source || fd < 0 || !metadata)
		return FALSE;
	
	// Go to the beginning of the BitLocker header
	xlseek(fd, source, SEEK_SET);
	
	xprintf(L_INFO, "Reading bitlocker header at %#" F_OFF_T "...\n", source);
	
	bitlocker_header_t bl_header;
	
	/*
	 * Read and place data into the bitlocker_header_t structure,
	 * this is the metadata header
	 */
	ssize_t nb_read = xread(fd, &bl_header, sizeof(bitlocker_header_t));
	
	// Check if we read all we wanted
	if(nb_read != sizeof(bitlocker_header_t))
	{
		xprintf(L_ERROR, "get_metadata::Error, not all bytes read: %d, %d"
				" expected (1).\n", nb_read, sizeof(bitlocker_header_t));
		return FALSE;
	}
	
	/*
	 * Now that we now the size of the metadata, allocate a buffer and read data
	 * to complete it
	 */
	size_t size = (size_t)(bl_header.version == V_SEVEN ?
	                                      bl_header.size << 4 : bl_header.size);
	
	
	if(size <= sizeof(bitlocker_header_t))
	{
		xprintf(L_ERROR, "get_metadata::Error, metadata size is lesser than the"
				" size of the metadata header\n");
		return FALSE;
	}
	
	size_t rest_size = size - sizeof(bitlocker_header_t);
	
	*metadata = xmalloc(size);
	
	// Copy the header at the begining of the metadata
	memcpy(*metadata, &bl_header, sizeof(bitlocker_header_t));
	
	xprintf(L_INFO, "Reading data...\n");
	
	// Read the rest, the real data
	nb_read = xread(fd, *metadata + sizeof(bitlocker_header_t), rest_size);
	
	// Check if we read all we wanted
	if((size_t) nb_read != rest_size)
	{
		xprintf(L_ERROR, "get_metadata::Error, not all bytes read: %d, %d"
				" expected (2).\n", nb_read, rest_size);
		return FALSE;
	}
	
	xprintf(L_INFO, "End get_metadata.\n");
	
	return TRUE;
}


/**
 * Get the dataset in the metadata
 * No allocation is performed
 * 
 * @param metadata The one to check for a dataset
 * @param dataset The resulting dataset
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_dataset(void* metadata, bitlocker_dataset_t** dataset)
{
	// Check parameters
	if(!metadata)
		return FALSE;
	
	*dataset = metadata + 0x40;
	
	/* Check this dataset validity */
	if(
		(*dataset)->copy_size < (*dataset)->header_size
		|| (*dataset)->size   > (*dataset)->copy_size
		|| (*dataset)->copy_size - (*dataset)->header_size < 8
	)
		return FALSE;
	
	return TRUE;
}


/**
 * This function reads the EOW information in two phases: first the header, then
 * the payload.
 * 
 * @param source The beginning address of the EOW information
 * @param eow_infos One of the EOW information, beginning at source
 * @param fd A file descriptor to the volume
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_eow_information(off_t source, void** eow_infos, int fd)
{
	if(!source || fd < 0 || !eow_infos)
		return FALSE;
	
	/* Go to the beginning of the EOW Information header */
	xlseek(fd, source, SEEK_SET);
	
	xprintf(L_DEBUG, "Reading EOW Information header at %#" F_OFF_T "...\n",
	        source);
	
	bitlocker_eow_infos_t eow_infos_hdr;
	
	/*
	 * Read and place data into the bitlocker_eow_infos_t structure,
	 * this is the EOW information header
	 */
	ssize_t nb_read = xread(fd, &eow_infos_hdr, sizeof(bitlocker_eow_infos_t));
	
	// Check if we read all we wanted
	if(nb_read != sizeof(bitlocker_eow_infos_t))
	{
		xprintf(L_ERROR, "get_eow_information::Error, not all bytes read: %d,"
		        " %d expected (1).\n", nb_read, sizeof(bitlocker_eow_infos_t));
		return FALSE;
	}
	
	size_t size = eow_infos_hdr.infos_size;
	
	if(size <= sizeof(bitlocker_eow_infos_t))
	{
		xprintf(L_ERROR, "get_eow_information::Error, EOW information size is"
		        " lesser than the size of the header\n");
		return FALSE;
	}
	
	size_t rest_size = size - sizeof(bitlocker_header_t);
	
	*eow_infos = xmalloc(size);
	
	// Copy the header at the begining of the EOW information
	memcpy(*eow_infos, &eow_infos_hdr, sizeof(bitlocker_eow_infos_t));
	
	xprintf(L_INFO, "Reading EOW information's payload...\n");
	
	// Read the rest, the payload
	nb_read = xread(fd, *eow_infos + sizeof(bitlocker_eow_infos_t), rest_size);
	
	// Check if we read all we wanted
	if((size_t) nb_read != rest_size)
	{
		xprintf(L_ERROR, "get_eow_information::Error, not all bytes read: %d, "
		        "%d expected (2).\n", nb_read, rest_size);
		return FALSE;
	}
	
	xprintf(L_INFO, "End get_eow_information.\n");
	
	
	return TRUE;
}


/**
 * This function compute the real offsets when the metadata_lcn doesn't equal 0
 * This is because of Vista which compute offsets differently than Seven
 * 
 * @param vh The volume header structure already taken
 * @param fd The opened file descriptor of the volume
 * @param offset Initial partition offset
 * @return TRUE if result can be trusted, FALSE otherwise
 */
static int compute_real_offsets(volume_header_t* vh, int fd, off_t offset)
{
	// Check parameters
	if(!vh || fd < 0)
		return FALSE;
	
	/* This is when the volume has been encrypted with W$ 7 or 8 */
	if(vh->metadata_lcn == 0)
		return TRUE;
	
	/* And when encrypted with W$ Vista: */
	xprintf(L_DEBUG,
		"MetadataLcn = %llu | SectorsPerCluster = %llu | SectorSize = %llu\n",
		vh->metadata_lcn, vh->sectors_per_cluster, vh->sector_size
	);
	
	uint64_t new_offset = vh->metadata_lcn * vh->sectors_per_cluster * vh->sector_size;
	xprintf(L_INFO, "Changing first metadata offset from %#llx to %#llx\n", vh->offset_bl_header[0], new_offset);
	vh->offset_bl_header[0] = new_offset;
	
	/* Now that we have the first offset, go get the others */
	bitlocker_header_t* metadata = NULL;
	if(!get_metadata((off_t)new_offset + offset, (void**)&metadata, fd))
		return FALSE;
	
	vh->offset_bl_header[1] = metadata->offset_bl_header[1];
	vh->offset_bl_header[2] = metadata->offset_bl_header[2];
	
	xfree(metadata);
	
	return TRUE;
}


/**
 * Get metadata/validations one by one, stop at the first valid
 * If a metadata block is forced to be taken, use this one without validation
 * 
 * @param volume_header The volume header structure already taken
 * @param fd The opened file descriptor of the volume
 * @param metadata A validated metadata resulting of this function
 * @param cfg Config asked by the user and used
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_metadata_check_validations(volume_header_t *volume_header, int fd, void **metadata, dis_config_t* cfg)
{
	// Check parameters
	if(!volume_header || fd < 0 || !metadata || !cfg)
		return FALSE;
	
	xprintf(L_DEBUG, "Entering get_metadata_check_validations\n");
	
	bitlocker_header_t* metadata_header = NULL;
	unsigned int  metadata_size = 0;
	unsigned char current = 0;
	unsigned int  metadata_crc32 = 0;
	off_t         validations_offset = 0;
	bitlocker_validations_infos_t validations;
	
	if(!compute_real_offsets(volume_header, fd, cfg->offset))
	{
		xprintf(L_ERROR, "Cannot get valid metadata offsets, aborting.\n");
		return FALSE;
	}
	
	/* If the user wants a specific metadata block */
	if(cfg->force_block != 0)
	{
		xprintf(L_INFO, "Obtaining block n°%d, forced by user...\n", cfg->force_block);
		// Get the metadata
		if(!get_metadata((off_t)volume_header->offset_bl_header[cfg->force_block-1] + cfg->offset, metadata, fd))
		{
			xprintf(L_ERROR, "Can't get metadata (n°%d, forced by user)\n", cfg->force_block);
			return FALSE;
		}
		
		xprintf(L_INFO, "Block n°%d obtained\n", cfg->force_block);
		
		return TRUE;
	}
	
	while(current < 3)
	{
		/* Get the metadata */
		if(!get_metadata((off_t)volume_header->offset_bl_header[current] + cfg->offset, metadata, fd))
		{
			xprintf(L_ERROR, "Can't get metadata (n°%d)\n", current+1);
			return FALSE;
		}
		
		
		/* Check some small things */
		
		
		/* Calculate validations offset */
		validations_offset = 0;
		metadata_header = (bitlocker_header_t*) *metadata;
		metadata_size = (unsigned int)(metadata_header->version == V_SEVEN ? ((unsigned int)metadata_header->size) << 4 : metadata_header->size);
		
		validations_offset = (off_t)volume_header->offset_bl_header[current] + metadata_size;
		
		xprintf(L_INFO, "Reading validations data at offset %#llx.\n", validations_offset);
		
		
		/* Go to the beginning of the BitLocker validation header */
		xlseek(fd, validations_offset + cfg->offset, SEEK_SET);
		
		/* Get the validations metadata */
		memset(&validations, 0, sizeof(bitlocker_validations_infos_t));
		
		ssize_t nb_read = xread(fd, &validations, sizeof(bitlocker_validations_infos_t));
		if(nb_read != sizeof(bitlocker_validations_infos_t))
		{
			xprintf(L_ERROR, "Error, can't read all validations data.\n");
			return FALSE;
		}
		
		/* Check the validity */
		metadata_crc32 = crc32((unsigned char*)*metadata, metadata_size);
		
		/*
		 * TODO add the thing with the datum contained in this validation metadata
		 * this provides a better checksum (sha256 hash)
		 *  => This needs the VMK (decrypted)
		 */
		xprintf(L_INFO, "Looking if %#x == %#x for metadata validation\n",
		        metadata_crc32, validations.crc32);
		
		++current;
		if(metadata_crc32 == validations.crc32)
		{
			cfg->force_block = current;
			xprintf(L_INFO, "We have a winner (n°%d)!\n", cfg->force_block);
			break;
		}
		else
			xfree(*metadata);
	}
	
	return TRUE;
}


/**
 * Get the EOW information structure one by one, stop at the first valid
 * 
 * @param volume_header The volume header structure already taken
 * @param fd The opened file descriptor of the volume
 * @param eow_infos The EOW information resulting of this function
 * @param cfg Configuration used
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_eow_check_valid(volume_header_t *volume_header, int fd, void **eow_infos, dis_config_t* cfg)
{
	// Check parameters
	if(!volume_header || fd < 0 || !eow_infos || !cfg)
		return FALSE;
	
	xprintf(L_DEBUG, "Entering get_eow_check_valid\n");
	
	bitlocker_eow_infos_t *eow_infos_hdr = NULL;
	unsigned char current = 0;
	unsigned int  eow_infos_size = 0;
	unsigned int  computed_crc32 = 0;
	off_t         curr_offset = 0;
	int           payload_size = 0;
	
	while(current < 2)
	{
		/* Compute the on-disk offset */
		curr_offset = (off_t)volume_header->offset_eow_information[current]
		            + cfg->offset;
		++current;
		
		/* Get the EOW information */
		if(!get_eow_information(curr_offset, eow_infos, fd))
		{
			xprintf(L_ERROR, "Can't get EOW information (n°%d)\n", current);
			return FALSE;
		}
		
		eow_infos_hdr = (bitlocker_eow_infos_t*) *eow_infos;
		
		
		/* Check some small things */
		
		/* Check sizes */
		if(eow_infos_hdr->infos_size <= eow_infos_hdr->header_size)
		{
			xfree(*eow_infos);
			continue;
		}
		
		/* Check size & number of regions */
		payload_size = eow_infos_hdr->infos_size - eow_infos_hdr->header_size;
		if((payload_size & 7)
			|| eow_infos_hdr->nb_regions != (uint32_t)(payload_size >> 3))
		{
			xfree(*eow_infos);
			continue;
		}
		
		/* Check the crc32 validity */
		eow_infos_size = eow_infos_hdr->infos_size;
		computed_crc32 = crc32((unsigned char*)*eow_infos, eow_infos_size);
		
		xprintf(L_INFO, "Looking if %#x == %#x for EOW information validation\n",
		        computed_crc32, eow_infos_hdr->crc32);
		
		if(computed_crc32 == eow_infos_hdr->crc32)
		{
			xprintf(L_INFO, "We have a winner (n°%d)!\n", current);
			break;
		}
		else
		{
			xfree(*eow_infos);
		}
	}
	
	return TRUE;
}


/**
 * Check for dangerous state the BitLocker volume can be in.
 * 
 * @param metadata The BitLocker metadata header
 * @return TRUE if it's safe to use the volume, FALSE otherwise
 */
int check_state(bitlocker_header_t* metadata)
{
	// Check parameter
	if(!metadata)
		return FALSE;
	
	char* enc = "enc";
	char* dec = "dec";
	char* unknown = "unknown-";
	char* next_state = NULL;
	
	if(metadata->next_state == DECRYPTED)
		next_state = dec;
	else if(metadata->next_state == ENCRYPTED)
		next_state = enc;
	else
	{
		next_state = unknown;
		xprintf(L_WARNING,
			"The next state of the volume is currently unknown of " PROGNAME
			", but it would be awesome if you could spare some time to report "
			"this state (%d) to the author and how did you do to have this. "
			"Many thanks.\n",
			metadata->next_state
		);
	}
	
	switch(metadata->curr_state)
	{
		case SWITCHING_ENCRYPTION:
			xprintf(L_ERROR,
				"The volume is currently being %srypted, which is an unstable "
				"state. If you know what you're doing, pass `-s' to the command"
				" line, but be aware it may result in data corruption.\n",
				next_state
			);
			return FALSE;
		case SWITCH_ENCRYPTION_PAUSED:
			xprintf(L_WARNING,
				"The volume is currently in a secure state, "
				"but don't resume the %sryption while using " PROGNAME " for "
				"the volume would become instable, resulting in data "
				"corruption.\n",
				next_state
			);
			break;
		case DECRYPTED:
			xprintf(L_WARNING,
				"The disk is about to get encrypted. Don't use " PROGNAME " if "
				"you're willing to do so, this may corrupt your data.\n"
			);
	}
	
	return TRUE;
}


