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
#include "metadata/metadata.h"
#include "read_bekfile.h"


int get_bek_dataset(int fd, void** bek_dataset)
{
	if(!bek_dataset)
	{
		xprintf(L_ERROR, "Invalid parameter given to get_bek_dataset().\n");
		return FALSE;
	}
	
	bitlocker_dataset_t dataset;
	
	/* Read the dataset header */
	ssize_t nb_read = xread(fd, &dataset, sizeof(bitlocker_dataset_t));
	
	// Check if we read all we wanted
	if(nb_read != sizeof(bitlocker_dataset_t))
	{
		xprintf(L_ERROR, "get_bek_dataset::Error, not all byte read (bek dataset header).\n");
		return FALSE;
	}
	
	if(dataset.size <= sizeof(bitlocker_dataset_t))
	{
		xprintf(L_ERROR, "get_bek_dataset::Error, dataset size < dataset header size.\n");
		return FALSE;
	}
	
	*bek_dataset = xmalloc(dataset.size);
	
	memset(*bek_dataset, 0, dataset.size);
	memcpy(*bek_dataset, &dataset, sizeof(bitlocker_dataset_t));
	
	size_t rest = dataset.size - sizeof(bitlocker_dataset_t);
	
	/* Read the data included in the dataset */
	nb_read = xread(fd, *bek_dataset + sizeof(bitlocker_dataset_t), rest);
	
	// Check if we read all we wanted
	if((size_t) nb_read != rest)
	{
		xprintf(L_ERROR, "get_bek_dataset::Error, not all byte read (bek dataset content).\n");
		return FALSE;
	}
	
	return TRUE;
}
