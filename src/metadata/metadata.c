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
	if(!volume_header)
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
 * Print a volume header structure into a human-readable format
 * 
 * @param volume_header The volume header to print
 */
void print_volume_header(LEVELS level, volume_header_t *volume_header)
{
	char rec_id[37];
	
	format_guid(volume_header->guid, rec_id);
	
	
	xprintf(level, "=====[ Volume header informations ]=====\n");
	xprintf(level, "  Signature: '%.8s'\n", volume_header->signature);
	xprintf(level, "  Sector size: 0x%1$04x (%1$hu) bytes\n", volume_header->sector_size);
	xprintf(level, "  Sector per cluster: 0x%1$02x (%1$hhu) bytes\n", volume_header->sectors_per_cluster);
	xprintf(level, "  Reserved clusters: 0x%1$04x (%1$hu) bytes\n", volume_header->reserved_clusters);
	xprintf(level, "  Fat count: 0x%1$02x (%1$hhu) bytes\n", volume_header->fat_count);
	xprintf(level, "  Root entries: 0x%1$04x (%1$hu) bytes\n", volume_header->root_entries);
	xprintf(level, "  Number of sectors (16 bits): 0x%1$04x (%1$hu) bytes\n", volume_header->nb_sectors_16b);
	xprintf(level, "  Media descriptor: 0x%1$02x (%1$hhu) bytes\n", volume_header->media_descriptor);
	xprintf(level, "  Sectors per fat: 0x%1$04x (%1$hu) bytes\n", volume_header->sectors_per_fat);
	xprintf(level, "  Hidden sectors: 0x%1$08x (%1$u) bytes\n", volume_header->hidden_sectors);
	xprintf(level, "  Number of sectors (32 bits): 0x%1$08x (%1$u) bytes\n", volume_header->nb_sectors_32b);
	xprintf(level, "  Number of sectors (64 bits): 0x%1$016x (%1$llu) bytes\n", volume_header->nb_sectors_64b);
	xprintf(level, "  MFT start cluster: 0x%1$016x (%1$lu) bytes\n", volume_header->mft_start_cluster);
	xprintf(level, "  Metadata Lcn: 0x%1$016x (%1$lu) bytes\n", volume_header->metadata_lcn);
	
	xprintf(level, "  Volume GUID: '%.37s'\n", rec_id);
	
	xprintf(level, "  First metadata header offset:  0x%016" F_U64_T "\n", volume_header->offset_bl_header[0]);
	xprintf(level, "  Second metadata header offset: 0x%016" F_U64_T "\n", volume_header->offset_bl_header[1]);
	xprintf(level, "  Third metadata header offset:  0x%016" F_U64_T "\n", volume_header->offset_bl_header[2]);
	
	xprintf(level, "  Boot Partition Identifier: '0x%04hx'\n", volume_header->boot_partition_identifier);
	xprintf(level, "========================================\n");
}


/**
 * Read one of BitLocker metadata and put data in a bitlocker_header_t structure
 * This also take the dataset header as it's in the bitlocker_header_t
 * Then read all metadata
 * 
 * @param source The beginning address of the header
 * @param metadata One of the BitLocker metadata, beginning at source
 * @param fd A file descriptor to the volume
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_metadata(off_t source, void **metadata, int fd)
{
	if(!source || fd <= 0)
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
	
	// Copy the header at thebeginning of the metadata
	memcpy(*metadata, &bl_header, sizeof(bitlocker_header_t));
	
	xprintf(L_INFO, "Reading data...\n");
	
	// Read the rest, the real data
	nb_read = xread(fd, *metadata + sizeof(bitlocker_header_t), rest_size);
	
	// Check if we read all we wanted
	if((size_t) nb_read != rest_size)
	{
		xprintf(L_ERROR, "get_metadata::Error, not all bytes read: %d, %d"
				" expected (2).\n");
		return FALSE;
	}
	
	xprintf(L_INFO, "End get_metadata.\n");
	
	return TRUE;
}


/**
 * Print a BitLocker header structure into a human-readable format
 * 
 * @param bl_header The BitLocker header to print
 */
void print_bl_metadata(LEVELS level, bitlocker_header_t *bl_header)
{
	time_t ts;
	bitlocker_dataset_t bl_dataset = bl_header->dataset;
	char* cipher = cipherstr(bl_dataset.algorithm);
	char formated_guid[37];
	
	format_guid(bl_dataset.guid, formated_guid);
	ntfs2utc(bl_dataset.timestamp, &ts);
	
	
	xprintf(level, "=====================[ BitLocker metadata informations ]=====================\n");
	xprintf(level, "  Signature: '%.8s'\n", bl_header->signature);
	xprintf(level, "  Total Size: 0x%1$04x (%1$d) bytes (including signature and data)\n", bl_header->size << 4);
	xprintf(level, "  Version: %hu\n", bl_header->version);
	if(bl_header->version == V_SEVEN)
	{
		hexdump(level, bl_header->unknown1, 4);
		xprintf(level, "  Encrypted volume size: %1$llu bytes (%1$#llx), ~%2$llu MB\n", bl_header->encrypted_volume_size, bl_header->encrypted_volume_size / (1024*1024));
		hexdump(level, bl_header->unknown2, 4);
		xprintf(level, "  Number of boot sectors backuped: %1$u sectors (%1$#x)\n", bl_header->nb_backup_sectors);
	}
	else
		hexdump(level, bl_header->unknown1, 20);
#ifdef __ARCH_X86_64
	xprintf(level, "  First metadata header offset:  %#lx\n", bl_header->offset_bl_header[0]);
	xprintf(level, "  Second metadata header offset: %#lx\n", bl_header->offset_bl_header[1]);
	xprintf(level, "  Third metadata header offset:  %#lx\n", bl_header->offset_bl_header[2]);
	xprintf(level, "  Boot sectors backup address:   %#lx\n", bl_header->boot_sectors_backup);
#else
	xprintf(level, "  First metadata header offset:  %#llx\n", bl_header->offset_bl_header[0]);
	xprintf(level, "  Second metadata header offset: %#llx\n", bl_header->offset_bl_header[1]);
	xprintf(level, "  Third metadata header offset:  %#llx\n", bl_header->offset_bl_header[2]);
	xprintf(level, "  Boot sectors backup address:   %#llx\n", bl_header->boot_sectors_backup);
#endif
	
	xprintf(level, "  ----------------------------{ Dataset header }----------------------------\n");
	xprintf(level, "    Dataset size: 0x%1$08x (%1$d) bytes (including data)\n", bl_dataset.size);
	xprintf(level, "    Unknown data: 0x%08x (always 0x00000001)\n", bl_dataset.unknown1);
	xprintf(level, "    Dataset header size: 0x%08x (always 0x00000030)\n", bl_dataset.header_size);
	xprintf(level, "    Dataset copy size: 0x%1$08x (%1$d) bytes\n", bl_dataset.copy_size);
	xprintf(level, "    Dataset GUID: '%.39s'\n", formated_guid);
	xprintf(level, "    Next counter: %u\n", bl_dataset.next_counter);
	xprintf(level, "    Encryption Type: %s (%#hx)\n", cipher, bl_dataset.algorithm);
	xprintf(level, "    Epoch Timestamp: %d sec, that to say %s\n", (int)ts, asctime(gmtime(&ts)));
	xprintf(level, "  --------------------------------------------------------------------------\n");
	xprintf(level, "=============================================================================\n");
	
	xfree(cipher);
}


/**
 * Get the dataset in the metadata
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
 * Print data of a given metadata
 * 
 * @param metadata The metadata from where data will be printed
 */
void print_data(LEVELS level, void* metadata)
{
	// Check parameters
	if(!metadata)
		return;
	
	bitlocker_dataset_t* dataset = NULL;
	void* data = NULL;
	void* end_dataset = 0;
	int loop = 0;
	
	if(!get_dataset(metadata, &dataset) || !dataset)
	{
		xprintf(L_ERROR, "Error, no dataset found.\n");
		return;
	}
	
	data = (char*)dataset + dataset->header_size;
	end_dataset = (char*)dataset + dataset->size;
	
	while(1)
	{
		/* Begin with reading the header */
		datum_header_safe_t header;
		
		if(data >= end_dataset)
			break;
		
		if(!get_header_safe(data, &header))
			break;
		
		if(data + header.datum_size > end_dataset)
			break;
		
		xprintf(level, "\n");
		xprintf(level, "======[ Datum n°%d informations ]======\n", ++loop);
		print_one_datum(level, data);
		xprintf(level, "=========================================\n");
		
		data += header.datum_size;
	}
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
	if(!vh)
		return FALSE;
	
	/* This is when the volume has been encrypted with W$ Seven */
	if(vh->metadata_lcn == 0)
		return TRUE;
	
	
	print_volume_header(L_DEBUG, vh);
	
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
	if(!volume_header || fd < 0 || !cfg)
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
		metadata_crc32 = 0;
		metadata_crc32 = crc32((unsigned char*)*metadata, metadata_size);
		
		/*
		 * TODO add the thing with the datum contained in this validation metadata
		 * this provides a better checksum (sha256 hash)
		 *  => This needs the VMK (decrypted)
		 */
		xprintf(L_INFO, "Looking if %#x == %#x for metadata validation\n", metadata_crc32, validations.crc32);
		
		++current;
		if(metadata_crc32 == validations.crc32)
		{
			cfg->force_block = current;
			xprintf(L_INFO, "We have a winner (n°%d)!\n", cfg->force_block);
			break;
		}
	}
	
	if(current == 3)
		xfree(*metadata);
	
	return TRUE;
}


/**
 * Check if a clear key is stored in data
 * 
 * @param metadata The metadata where to look
 * @param vmk_datum The VMK datum of the clear key if found
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int has_clear_key(void* dataset, datum_vmk_t** vmk_datum)
{
	if(!dataset)
		return FALSE;
	
	*vmk_datum = NULL;
	
	xprintf(L_DEBUG, "Entering has_clear_key. Returning result of get_vmk_datum_from_range with range between 0x00 and 0xff\n");
	
	return get_vmk_datum_from_range(dataset, 0x00, 0xff, (void**)vmk_datum);
}




