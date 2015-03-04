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

#include "dislocker/encryption/crc32.h"
#include "dislocker/metadata/metadata.h"
#include "dislocker/metadata/print_metadata.h"


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
 * Get BitLocker's version from the volume header
 * 
 * @param volume_header A volume header structure to check
 * @return V_VISTA or V_SEVEN according to the version found, or -1 if not
 * recognized
 */
static inline int get_version_from_volume_header(volume_header_t *volume_header)
{
	if(memcmp(BITLOCKER_SIGNATURE, volume_header->signature,
	          BITLOCKER_SIGNATURE_SIZE) == 0)
	{
		if(volume_header->metadata_lcn == 0)
			return V_SEVEN;
		
		return V_VISTA;
	}
	
	return -1;
}


/**
 * Check the volume header
 * 
 * @param volume_header A volume header structure to check
 * @param volume_fd The opened file descriptor of the BitLocker volume
 * @param cfg Config asked by the user and used
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int check_volume_header(volume_header_t *volume_header, int volume_fd, dis_config_t *cfg)
{
	if(!volume_header || volume_fd < 0 || !cfg)
		return FALSE;
	
	guid_t volume_guid;
	
	/* Checking sector size */
	if(volume_header->sector_size == 0)
	{
		xprintf(L_ERROR, "The sector size found is null.\n");
		return FALSE;
	}
	
	/* Check the signature */
	if(memcmp(BITLOCKER_SIGNATURE, volume_header->signature,
	          BITLOCKER_SIGNATURE_SIZE) == 0)
	{
		memcpy(volume_guid, volume_header->guid, sizeof(guid_t));
	}
	else if(memcmp(BITLOCKER_TO_GO_SIGNATURE, volume_header->signature,
	               BITLOCKER_TO_GO_SIGNATURE_SIZE) == 0)
	{
		memcpy(volume_guid, volume_header->bltg_guid, sizeof(guid_t));
	}
	else
	{
		xprintf(
		        L_ERROR,
		        "The signature of the volume (%.8s) doesn't match the "
		        "BitLocker's ones (" BITLOCKER_SIGNATURE " or "
		        BITLOCKER_TO_GO_SIGNATURE "). Abort.\n",
		        volume_header->signature
		);
		return FALSE;
	}
	
	
	/*
	 * There's no BitLocker GUID in the volume header for volumes encrypted by
	 * Vista
	 */
	if(get_version_from_volume_header(volume_header) == V_VISTA)
		return TRUE;
	
	
	/* Check if we're running under EOW mode */
	extern guid_t INFORMATION_OFFSET_GUID, EOW_INFORMATION_OFFSET_GUID;
	
	if(check_match_guid(volume_guid, INFORMATION_OFFSET_GUID))
	{
		xprintf(L_INFO, "Volume GUID (INFORMATION OFFSET) supported\n");
	}
	else if(check_match_guid(volume_guid, EOW_INFORMATION_OFFSET_GUID))
	{
		xprintf(L_INFO, "Volume has EOW_INFORMATION_OFFSET_GUID.\n");
		
		// First: get the EOW informations no matter what
		off_t source = (off_t) volume_header->eow_information_off[0];
		void* eow_infos = NULL;
		
		if(get_eow_information(source, &eow_infos, volume_fd))
		{
			// Second: print them
			print_eow_infos(L_DEBUG, (bitlocker_eow_infos_t*)eow_infos);
			
			xfree(eow_infos);
			
			// Third: check if this struct passes checks
			if(get_eow_check_valid(volume_header, volume_fd, &eow_infos, cfg))
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
		
		xprintf(L_ERROR, "EOW volume GUID not supported.\n");
		return FALSE;
	}
	else
	{
		xprintf(L_ERROR, "Unknown volume GUID not supported.\n");
		return FALSE;
	}
	
	return TRUE;
}


/**
 * This function compute the real offsets when the metadata_lcn doesn't equal 0
 * This is because of Vista which compute offsets differently than Seven
 * This also takes into account BitLocker-to-go's volume header structure
 * difference in the offsets
 * 
 * @param vh The volume header structure already taken
 * @param fd The opened file descriptor of the BitLocker volume
 * @param disk_offset Initial partition offset
 * @param regions The 3 offsets of the BitLocker INFORMATION structure (which
 * corresponds to our bitlocker_information_t structure) will be put in the 3
 * first addr member of this array
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int begin_compute_regions(volume_header_t* vh,
                          int fd,
                          off_t disk_offset,
                          dis_regions_t* regions)
{
	// Check parameters
	if(!vh || fd < 0)
		return FALSE;
	
	
	if(memcmp(BITLOCKER_SIGNATURE, vh->signature,
	          BITLOCKER_SIGNATURE_SIZE) == 0)
	{
		/* This is when the volume has been encrypted with W$ 7 or 8 */
		if(get_version_from_volume_header(vh) == V_SEVEN)
		{
			regions[0].addr = vh->information_off[0];
			regions[1].addr = vh->information_off[1];
			regions[2].addr = vh->information_off[2];
			return TRUE;
		}
		
		/* And when encrypted with W$ Vista: */
		xprintf(L_DEBUG,
			"MetadataLcn = %llu | SectorsPerCluster = %llu | SectorSize = %llu\n",
			vh->metadata_lcn, vh->sectors_per_cluster, vh->sector_size
		);
		
		uint64_t new_offset = vh->metadata_lcn * vh->sectors_per_cluster * vh->sector_size;
		xprintf(L_INFO, "Changing first metadata offset from %#llx to %#llx\n", vh->information_off[0], new_offset);
		regions[0].addr = new_offset;
		
		/* Now that we have the first offset, go get the others */
		bitlocker_information_t* information = NULL;
		if(!get_metadata((off_t)new_offset + disk_offset, (void**)&information, fd))
			return FALSE;
		
		regions[1].addr = information->information_off[1];
		regions[2].addr = information->information_off[2];
		
		xfree(information);
	}
	else if(memcmp(BITLOCKER_TO_GO_SIGNATURE, vh->signature,
	               BITLOCKER_TO_GO_SIGNATURE_SIZE) == 0)
	{
		regions[0].addr = vh->bltg_header[0];
		regions[1].addr = vh->bltg_header[1];
		regions[2].addr = vh->bltg_header[2];
	}
	else
	{
		xprintf(L_ERROR, "Wtf!? Unknown volume GUID not supported.");
		return FALSE;
	}
	
	return TRUE;
}


/**
 * This finalizes the initialization of the regions informations, putting the
 * metadata file sizes in the right place.
 * 
 * @param regions Where to put regions' sizes
 * @param volume_header The volume header structure
 * @param information One of the BitLocker information structure
 * @return -1 on failure, the number of virtualized regions
 */
int end_compute_regions(dis_regions_t* regions, volume_header_t* volume_header,
                        bitlocker_information_t* information)
{
	if(!regions || !volume_header || !information)
		return -1;
	
	uint16_t sector_size         = volume_header->sector_size;
	uint8_t  sectors_per_cluster = volume_header->sectors_per_cluster;
	uint32_t cluster_size        = 0;
	uint64_t metafiles_size      = 0;
	
	int nb_virt_region = 0;
	
	/*
	 * Alignment isn't the same for W$ Vista (size-of-a-cluster aligned on
	 * 0x4000) and 7&8 (size-of-a-sector aligned on 0x10000).
	 * This gives the metadata files' sizes in the NTFS layer.
	 */
	if(information->version == V_VISTA)
	{
		cluster_size   = (uint32_t)sector_size * sectors_per_cluster;
		metafiles_size = (uint64_t)(cluster_size+0x3fff) & ~(cluster_size-1);
	}
	else if(information->version == V_SEVEN)
	{
		metafiles_size = (uint64_t)(~(sector_size-1) & (sector_size+0xffff));
	}
	
	
	xprintf(
		L_DEBUG,
		"Metadata files size: %#" F_U64_T "\n",
		metafiles_size
	);
	
	/*
	 * The first 3 regions are for INFORMATION metadata, they have the same size
	 */
	regions[0].size = metafiles_size;
	regions[1].size = metafiles_size;
	regions[2].size = metafiles_size;
	nb_virt_region = 3;
	
	
	if(information->version == V_VISTA)
	{
		// Nothing special to do
	}
	else if(information->version == V_SEVEN)
	{
		/*
		 * On BitLocker 7's volumes, there's a virtualized space used to store
		 * firsts NTFS sectors. BitLocker creates a NTFS file to not write on
		 * the area and displays a zeroes-filled file.
		 * A second part, new from Windows 8, follows...
		 */
		datum_virtualization_t* datum = NULL;
		if(!get_next_datum(&information->dataset, -1,
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
		
		nb_virt_region++;
		regions[3].addr = information->boot_sectors_backup;
		regions[3].size = datum->nb_bytes;
		
		/* Another area to report as filled with zeroes, new to W8 as well */
		if(information->curr_state == SWITCHING_ENCRYPTION)
		{
			nb_virt_region++;
			regions[4].addr = information->encrypted_volume_size;
			regions[4].size = information->unknown_size;
		}
	}
	else
	{
		/* Explicitly mark a BitLocker version as unsupported */
		xprintf(L_ERROR, "Unsupported BitLocker version (%hu)\n", information->version);
		return -1;
	}
	
	
	return nb_virt_region;
}


/**
 * Read the beginning of one of the BitLocker metadata area and put data in a
 * bitlocker_information_t structure.
 * This also take the dataset header as it's in the bitlocker_information_t.
 * Then includes datums in the read.
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
	
	bitlocker_information_t information;
	
	/*
	 * Read and place data into the bitlocker_information_t structure,
	 * this is the metadata's header
	 */
	ssize_t nb_read = xread(fd, &information, sizeof(bitlocker_information_t));
	
	// Check if we read all we wanted
	if(nb_read != sizeof(bitlocker_information_t))
	{
		xprintf(L_ERROR, "get_metadata::Error, not all bytes read: %d, %d"
				" expected (1).\n", nb_read, sizeof(bitlocker_information_t));
		return FALSE;
	}
	
	/*
	 * Now that we now the size of the metadata, allocate a buffer and read data
	 * to complete it
	 */
	size_t size = (size_t)(information.version == V_SEVEN ?
	                                  information.size << 4 : information.size);
	
	
	if(size <= sizeof(bitlocker_information_t))
	{
		xprintf(L_ERROR, "get_metadata::Error, metadata size is lesser than the"
				" size of the metadata header\n");
		return FALSE;
	}
	
	size_t rest_size = size - sizeof(bitlocker_information_t);
	
	*metadata = xmalloc(size);
	
	// Copy the header at the begining of the metadata
	memcpy(*metadata, &information, sizeof(bitlocker_information_t));
	
	xprintf(L_INFO, "Reading data...\n");
	
	// Read the rest, the real data
	nb_read = xread(fd, *metadata + sizeof(bitlocker_information_t), rest_size);
	
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
	
	bitlocker_information_t* information = metadata;
	*dataset = &information->dataset;
	
	/* Check this dataset validity */
	if(
		(*dataset)->copy_size < (*dataset)->header_size
		|| (*dataset)->size   > (*dataset)->copy_size
		|| (*dataset)->copy_size - (*dataset)->header_size < 8
	)
	{
		xprintf(L_DEBUG, "size=%#x, copy_size=%#x, header_size=%#x\n");
		return FALSE;
	}
	
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
	
	size_t rest_size = size - sizeof(bitlocker_information_t);
	
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
 * Get metadata/validations one by one, stop at the first valid
 * If a metadata block is forced to be taken, use this one without validation
 * 
 * @param volume_header The volume header structure already taken
 * @param fd The opened file descriptor of the volume
 * @param metadata A validated metadata resulting of this function
 * @param cfg Config asked by the user and used
 * @param regions Regions used by metadata, mostly the metadata's offsets for
 * use in this function
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_metadata_lazy_checked(volume_header_t *volume_header,
                                   int fd, void **metadata, dis_config_t *cfg,
                                   dis_regions_t *regions)
{
	// Check parameters
	if(!volume_header || fd < 0 || !metadata || !cfg)
		return FALSE;
	
	xprintf(L_DEBUG, "Entering get_metadata_lazy_checked\n");
	
	bitlocker_information_t* information = NULL;
	unsigned int  metadata_size = 0;
	unsigned char current = 0;
	unsigned int  metadata_crc32 = 0;
	off_t         validations_offset = 0;
	bitlocker_validations_t validations;
	
	/* If the user wants a specific metadata block */
	if(cfg->force_block != 0)
	{
		xprintf(L_INFO, "Obtaining block n°%d, forced by user...\n", cfg->force_block);
		// Get the metadata
		if(!get_metadata((off_t)regions[cfg->force_block-1].addr + cfg->offset, metadata, fd))
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
		if(!get_metadata((off_t)regions[current].addr + cfg->offset, metadata, fd))
		{
			xprintf(L_ERROR, "Can't get metadata (n°%d)\n", current+1);
			return FALSE;
		}
		
		
		/* Check some small things */
		
		
		/* Calculate validations offset */
		validations_offset = 0;
		information = *metadata;
		metadata_size = (unsigned int)(information->version == V_SEVEN ?
		            ((unsigned int)information->size) << 4 : information->size);
		
		validations_offset = (off_t)regions[current].addr + metadata_size;
		
		xprintf(L_INFO, "Reading validations data at offset %#llx.\n", validations_offset);
		
		
		/* Go to the beginning of the BitLocker validation header */
		xlseek(fd, validations_offset + cfg->offset, SEEK_SET);
		
		/* Get the validations metadata */
		memset(&validations, 0, sizeof(bitlocker_validations_t));
		
		ssize_t nb_read = xread(fd, &validations, sizeof(bitlocker_validations_t));
		if(nb_read != sizeof(bitlocker_validations_t))
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
		curr_offset = (off_t)volume_header->eow_information_off[current]
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
 * @param information The BitLocker metadata header
 * @return TRUE if it's safe to use the volume, FALSE otherwise
 */
int check_state(bitlocker_information_t* information)
{
	// Check parameter
	if(!information)
		return FALSE;
	
	char* enc = "enc";
	char* dec = "dec";
	char* unknown = "unknown-";
	char* next_state = NULL;
	
	if(information->next_state == DECRYPTED)
		next_state = dec;
	else if(information->next_state == ENCRYPTED)
		next_state = enc;
	else
	{
		next_state = unknown;
		xprintf(L_WARNING,
			"The next state of the volume is currently unknown of " PROGNAME
			", but it would be awesome if you could spare some time to report "
			"this state (%d) to the author and how did you do to have this. "
			"Many thanks.\n",
			information->next_state
		);
	}
	
	switch(information->curr_state)
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


