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
/*
 * BitLocker Encryption Key (BEK) structure reader.
 *
 * Ref:
 * - http://jessekornblum.com/publications/di09.pdf
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>

#include "common.h"
#include "read_bekfile.h"



void print_bek_header(dataset_t* bek) 
{
	time_t ts;
	char rec_id[37];
	
	ntfs2utc(bek->timestamp, &ts); 
	format_guid(bek->hash, rec_id); 
	
	xprintf(L_INFO, "==[ Generic BEK file information ]==\n");
	xprintf(L_INFO, "Total Size: %hu bytes\n", bek->size);
	xprintf(L_INFO, "Unknown: %hu\n", bek->unknown1);
	xprintf(L_INFO, "Header Size: %d bytes\n", bek->header_size);
	xprintf(L_INFO, "Recovery Key Id: %16s \n", rec_id);
	xprintf(L_INFO, "Next counter: %d\n", bek->next_counter);
	xprintf(L_INFO, "Reserved field: 0x%x\n", bek->algo_zeroed);  
	xprintf(L_INFO, "Epoch Timestamp: %ud sec, or %s\n", (unsigned int)ts, asctime(gmtime(&ts)));
}


void print_ext_info_header(external_info_header_t* header) 
{
	char rec_id[37] = {0,};
	time_t ts;
	char* type_str = NULL;
	
	ntfs2utc(header->timestamp, &ts);
	format_guid(header->guid, rec_id);
	type_str = datumtypestr(header->datum_type);
	
	xprintf(L_INFO, "===[ Header information ]===\n");
	xprintf(L_INFO, "Size: %hu bytes\n", header->size);
	xprintf(L_INFO, "Unknown1: %#.4x\n", header->unknown1);
	xprintf(L_INFO, "Datum type: %s (%#.4x)\n", type_str, header->datum_type);
	xprintf(L_INFO, "Error status: %hu\n", header->error_status);
	xprintf(L_INFO, "Recovery Key Id: %s\n", rec_id);
	xprintf(L_INFO, "Epoch Timestamp: %ud sec, or %s\n", (unsigned int)ts, asctime(gmtime(&ts)));
	
	xfree(type_str);
}


void print_key(key_header_t* key_hdr)
{
	char* cipher = cipherstr(key_hdr->algorithm);
	char* type_str = datumtypestr(key_hdr->datum_type);
	
	xprintf(L_INFO, "====[ Private Key Header information ]====\n");
	xprintf(L_INFO, "Size: %hu bytes\n", key_hdr->size);
	xprintf(L_INFO, "Unknown: %hu\n", key_hdr->zeros);
	xprintf(L_INFO, "Datum type: %s (%#hx)\n", type_str, key_hdr->datum_type);
	xprintf(L_INFO, "Encryption Type: %s (%#hx)\n", cipher, key_hdr->algorithm);
	xprintf(L_INFO, "Unknown1: \n"); 
	hexdump(L_INFO, key_hdr->unknown1, sizeof(key_hdr->unknown1));
	xprintf(L_INFO, "Decryption Key:\n");
	hexdump(L_INFO, key_hdr->decryption_key, sizeof(key_hdr->decryption_key));
	
	xfree(cipher);
	xfree(type_str);
}


void decode(int fd, dataset_t* bek_data, external_info_header_t* header, key_header_t* key_header)
{
	memset (bek_data, 0, sizeof(dataset_t));
	memset (header, 0, sizeof(external_info_header_t));
	memset (key_header, 0, sizeof(key_header_t));
	
	
	xread (fd, bek_data, sizeof(dataset_t));
	
	xread (fd, header, sizeof(external_info_header_t));
	
	xread (fd, key_header, sizeof(key_header_t));
}



int get_bek_dataset(int fd, void** bek_dataset)
{
	dataset_t dataset;
	
	/* Read the dataset header */
	ssize_t nb_read = xread(fd, &dataset, sizeof(dataset_t));
	
	// Check if we read all we wanted
	if(nb_read != sizeof(dataset_t))
	{
		xprintf(L_ERROR, "get_bek_dataset::Error, not all byte read (bek dataset header).\n");
		return FALSE;
	}
	
	if(dataset.size <= sizeof(dataset_t))
	{
		xprintf(L_ERROR, "get_bek_dataset::Error, dataset size < dataset header size.\n");
		return FALSE;
	}
	
	*bek_dataset = xmalloc(dataset.size);
	
	memset(*bek_dataset, 0, dataset.size);
	memcpy(*bek_dataset, &dataset, sizeof(dataset_t));
	
	size_t rest = dataset.size - sizeof(dataset_t);
	
	/* Read the data included in the dataset */
	nb_read = xread(fd, *bek_dataset + sizeof(dataset_t), rest);
	
	// Check if we read all we wanted
	if((size_t) nb_read != rest)
	{
		xprintf(L_ERROR, "get_bek_dataset::Error, not all byte read (bek dataset content).\n");
		return FALSE;
	}
	
	return TRUE;
}
