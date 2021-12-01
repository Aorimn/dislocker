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

#include <time.h>

#include "dislocker/metadata/metadata.priv.h"
#include "dislocker/metadata/datums.h"
#include "dislocker/metadata/print_metadata.h"


/** BitLocker's states into string */
static const char* states_str[] =
{
	"NULL",
	"DECRYPTED",
	"SWITCHING ENCRYPTION",
	"EOW ACTIVATED",
	"ENCRYPTED",
	"SWITCHING ENCRYPTION PAUSED",
	"UNKNOWN STATE (too big)"
};


/**
 * Print a volume header structure into a human-readable format
 *
 * @param level The level above which we're gonna print
 * @param dis_metadata The metadata structure
 */
void print_volume_header(DIS_LOGS level, dis_metadata_t dis_meta)
{
	if(!dis_meta)
		return;

	volume_header_t *volume_header = dis_meta->volume_header;

	char rec_id[37];

	format_guid(volume_header->guid, rec_id);


	dis_printf(level, "=====[ Volume header informations ]=====\n");
	dis_printf(level, "  Signature: '%.8s'\n", volume_header->signature);
	dis_printf(level, "  Sector size: 0x%1$04x (%1$hu) bytes\n", volume_header->sector_size);
	dis_printf(level, "  Sector per cluster: 0x%1$02x (%1$hhu) bytes\n", volume_header->sectors_per_cluster);
	dis_printf(level, "  Reserved clusters: 0x%1$04x (%1$hu) bytes\n", volume_header->reserved_clusters);
	dis_printf(level, "  Fat count: 0x%1$02x (%1$hhu) bytes\n", volume_header->fat_count);
	dis_printf(level, "  Root entries: 0x%1$04x (%1$hu) bytes\n", volume_header->root_entries);
	dis_printf(level, "  Number of sectors (16 bits): 0x%1$04x (%1$hu) bytes\n", volume_header->nb_sectors_16b);
	dis_printf(level, "  Media descriptor: 0x%1$02x (%1$hhu) bytes\n", volume_header->media_descriptor);
	dis_printf(level, "  Sectors per fat: 0x%1$04x (%1$hu) bytes\n", volume_header->sectors_per_fat);
	dis_printf(level, "  Hidden sectors: 0x%1$08x (%1$u) bytes\n", volume_header->hidden_sectors);
	dis_printf(level, "  Number of sectors (32 bits): 0x%1$08x (%1$u) bytes\n", volume_header->nb_sectors_32b);
	dis_printf(level, "  Number of sectors (64 bits): 0x%1$016" PRIx64 " (%1$" PRIu64 ") bytes\n", volume_header->nb_sectors_64b);
	dis_printf(level, "  MFT start cluster: 0x%1$016" PRIx64 " (%1$" PRIu64 ") bytes\n", volume_header->mft_start_cluster);
	dis_printf(level, "  Metadata Lcn: 0x%1$016" PRIx64 " (%1$" PRIu64 ") bytes\n", volume_header->metadata_lcn);

	dis_printf(level, "  Volume GUID: '%.37s'\n", rec_id);

	dis_printf(level, "  First metadata header offset:  0x%016" PRIx64 "\n", volume_header->information_off[0]);
	dis_printf(level, "  Second metadata header offset: 0x%016" PRIx64 "\n", volume_header->information_off[1]);
	dis_printf(level, "  Third metadata header offset:  0x%016" PRIx64 "\n", volume_header->information_off[2]);

	dis_printf(level, "  Boot Partition Identifier: '0x%04hx'\n", volume_header->boot_partition_identifier);
	dis_printf(level, "========================================\n");
}


/**
 * Return the state in which BitLocker is in as a (constant) string
 *
 * @param state The state to translate
 * @return The state as a constant string
 */
static const char* get_state_str(dis_metadata_state_t state)
{
	if(state >= sizeof(states_str) / sizeof(char*))
		return states_str[sizeof(states_str) / sizeof(char*) - 1];

	return states_str[state];
}


/**
 * Print a BitLocker header structure into a human-readable format
 *
 * @param level The level above which we're gonna print
 * @param dis_meta The metadata structure
 */
void print_information(DIS_LOGS level, dis_metadata_t dis_meta)
{
	if(!dis_meta)
		return;

	bitlocker_information_t *information = dis_meta->information;
	int metadata_size = information->version == V_SEVEN ? information->size << 4 : information->size;

	dis_printf(level, "=====================[ BitLocker information structure ]=====================\n");
	dis_printf(level, "  Signature: '%.8s'\n", information->signature);
	dis_printf(level, "  Total Size: 0x%1$04x (%1$u) bytes (including signature and data)\n", metadata_size);
	dis_printf(level, "  Version: %hu\n", information->version);
	dis_printf(level, "  Current state: %s (%hu)\n", get_state_str(information->curr_state), information->curr_state);
	dis_printf(level, "  Next state: %s (%hu)\n",    get_state_str(information->next_state), information->next_state);
	dis_printf(level, "  Encrypted volume size: %1$" PRIu64 " bytes (%1$#" PRIx64 "), ~%2$" PRIu64 " MB\n", information->encrypted_volume_size, information->encrypted_volume_size / (1024*1024));
	dis_printf(level, "  Size of conversion region: %1$#x (%1$u)\n", information->convert_size);
	dis_printf(level, "  Number of boot sectors backuped: %1$u sectors (%1$#x)\n", information->nb_backup_sectors);
	dis_printf(level, "  First metadata header offset:  %#" PRIx64 "\n", information->information_off[0]);
	dis_printf(level, "  Second metadata header offset: %#" PRIx64 "\n", information->information_off[1]);
	dis_printf(level, "  Third metadata header offset:  %#" PRIx64 "\n", information->information_off[2]);
	if(information->version == V_SEVEN)
		dis_printf(level, "  Boot sectors backup address:   %#" PRIx64 "\n", information->boot_sectors_backup);
	else
		dis_printf(level, "  NTFS MftMirror field:   %#" PRIx64 "\n", information->mftmirror_backup);

	print_dataset(level, dis_meta);
	dis_printf(level, "=============================================================================\n");
}


/**
 * Print a BitLocker dataset structure into human-readable format
 *
 * @param level The level above which we're gonna print
 * @param dis_metadata The metadata structure
 */
void print_dataset(DIS_LOGS level, dis_metadata_t dis_meta)
{
	if(!dis_meta)
		return;

	bitlocker_dataset_t* dataset = dis_meta->dataset;
	time_t ts;
	char* date = NULL;
	char* cipher = cipherstr(dataset->algorithm);
	char formated_guid[37];

	format_guid(dataset->guid, formated_guid);
	ntfs2utc(dataset->timestamp, &ts);
	date = strdup(asctime(gmtime(&ts)));
	chomp(date);

	dis_printf(level, "  ----------------------------{ Dataset header }----------------------------\n");
	dis_printf(level, "    Dataset size: 0x%1$08x (%1$d) bytes (including data)\n", dataset->size);
	dis_printf(level, "    Unknown data: 0x%08x (always 0x00000001)\n", dataset->unknown1);
	dis_printf(level, "    Dataset header size: 0x%08x (always 0x00000030)\n", dataset->header_size);
	dis_printf(level, "    Dataset copy size: 0x%1$08x (%1$d) bytes\n", dataset->copy_size);
	dis_printf(level, "    Dataset GUID: '%.39s'\n", formated_guid);
	dis_printf(level, "    Next counter: %u\n", dataset->next_counter);
	dis_printf(level, "    Encryption Type: %s (%#hx)\n", cipher, dataset->algorithm);
	dis_printf(level, "    Epoch Timestamp: %u sec, that to say %s\n", (unsigned int)ts, date);
	dis_printf(level, "  --------------------------------------------------------------------------\n");

	dis_free(cipher);
	free(date);
}


/**
 * Print a BitLocker EOW information structure into human-readable format
 *
 * @param dis_metadata The metadata structure
 */
void print_eow_infos(DIS_LOGS level, dis_metadata_t dis_meta)
{
	if(!dis_meta)
		return;

	bitlocker_eow_infos_t* eow_infos = dis_meta->eow_information;

	dis_printf(level, "=======================[ BitLocker EOW informations ]========================\n");
	dis_printf(level, "  Signature: '%.8s'\n", eow_infos->signature);
	dis_printf(level, "  Structure size: 0x%1$04x (%1$hu)\n", eow_infos->header_size);
	dis_printf(level, "  On-disk size: 0x%1$04x (%1$hu)\n", eow_infos->infos_size);
	dis_printf(level, "  Sector size (1): 0x%1$04x (%1$hu)\n", eow_infos->sector_size1);
	dis_printf(level, "  Sector size (2): 0x%1$04x (%1$hu)\n", eow_infos->sector_size2);

	dis_printf(level, "  Unknown (0x14): 0x%1$08x (%1$u)\n", eow_infos->unknown_14);

	dis_printf(level, "  Convlog size: 0x%1$08x (%1$u)\n", eow_infos->convlog_size);

	dis_printf(level, "  Unknown (0x1c): 0x%1$08x (%1$u)\n", eow_infos->unknown_1c);

	dis_printf(level, "  Number of regions: %u\n", eow_infos->nb_regions);
	dis_printf(level, "  Crc32: %x\n", eow_infos->crc32);
	dis_printf(level, "  On-disk offsets: %#" PRIx64 "\n", eow_infos->disk_offsets);
	dis_printf(level, "=============================================================================\n");
}


/**
 * Print data of a given metadata
 *
 * @param level The level above which we're gonna print
 * @param dis_metadata The metadata structure
 */
void print_data(DIS_LOGS level, dis_metadata_t dis_meta)
{
	// Check parameters
	if(!dis_meta)
		return;

	bitlocker_dataset_t* dataset = dis_meta->dataset;
	void* data = NULL;
	void* end_dataset = 0;
	int loop = 0;


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

		dis_printf(level, "\n");
		dis_printf(level, "=======[ Datum n°%d informations ]=======\n", ++loop);
		print_one_datum(level, data);
		dis_printf(level, "=========================================\n");

		data += header.datum_size;
	}
}
