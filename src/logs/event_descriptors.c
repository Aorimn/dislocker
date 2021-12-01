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

#include "event_descriptors.h"


void init_events()
{
	FVE_ENCRYPT_START = {
		.id = 0x6001
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_ENCRYPT_STOP = {
		.id = 0x6002
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_ENCRYPT_COMPLETE = {
		.id = 0x6003
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_DECRYPT_START = {
		.id = 0x6004
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_DECRYPT_STOP = {
		.id = 0x6005
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_DECRYPT_COMPLETE = {
		.id = 0x6006
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_CONV_RESUME = {
		.id = 0x6007
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_CONV_PAUSE = {
		.id = 0x6008
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_AUTOUNLOCK_ENABLE_OK = {
		.id = 0x6009
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_CONV_ERROR = {
		.id = 0x600a
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_AUTOUNLOCK_DISABLE_OK = {
		.id = 0x600b
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_CONV_SECTOR_ERROR = {
		.id = 0x600c
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_AUTOUNLOCK_ENABLE_ERROR = {
		.id = 0x600d
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_AUTOUNLOCK_DISABLE_ERROR = {
		.id = 0x600e
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_AUTOUNLOCK_ERROR = {
		.id = 0x600f
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_CONV_AUTO_START_FAILURE = {
		.id = 0x6010
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_DISK_FAILED_WRITE_ERROR = {
		.id = 0x6011
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_REBUILD_DATA_LOSS_ERROR = {
		.id = 0x6012
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_CONV_BAD_CLUSTERS_SKIPPED = {
		.id = 0x6013
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_INVALID_CONFIG = {
		.id = 0x601c
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_KEY_UNAVAILABLE = {
		.id = 0x6021
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_PARTIAL_COMMIT = {
		.id = 0x6022
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_FAILED_COMMIT = {
		.id = 0x6023
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_DISK_FAILED_FLUSH_ERROR = {
		.id = 0x6024
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_DISK_FAILED_READBACK_ERROR = {
		.id = 0x6025
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_DISK_FAILED_VERIFY_ERROR = {
		.id = 0x6026
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_CORRUPT_ERROR = {
		.id = 0x6027
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_FAILOVER_ERROR = {
		.id = 0x6028
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_FAILOVER = {
		.id = 0x6029
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_SUBSET = {
		.id = 0x602a
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_METADATA_REBUILD_DROP = {
		.id = 0x602b
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_INIT_FAILED_ERROR = {
		.id = 0x602c
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_CONV_RECOVERING = {
		.id = 0x602d
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_MOR_BIT_RUN_INIT_ERROR = {
		.id = 0x602f
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_MOR_BIT_SET_ERROR = {
		.id = 0x6030
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_KEY_OBTAINED = {
		.id = 0x6031
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_AUTOUNLOCK_NO_MASTER_KEY = {
		.id = 0x6032
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_DEBUGGER_ENABLED = {
		.id = 0x6033
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_BAD_PARTITION_SIZE = {
		.id = 0x6034
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_MOR_FAILED = {
		.id = 0x6035
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_KEYFILE_NOT_FOUND = {
		.id = 0x6036
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_KEYFILE_CORRUPT = {
		.id = 0x6037
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_KEYFILE_NO_VMK = {
		.id = 0x6038
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_TPM_DISABLED = {
		.id = 0x6039
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_TPM_INVALID_SRK = {
		.id = 0x603a
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_TPM_INVALID_PCR = {
		.id = 0x603b
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_TPM_NO_VMK = {
		.id = 0x603c
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_INVALID_APPLICATION = {
		.id = 0x603d
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_PIN_INVALID = {
		.id = 0x603e
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_PASSWORD_INVALID = {
		.id = 0x603f
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_GOT_KEY = {
		.id = 0x6040
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_UNEXPECTED = {
		.id = 0x6041
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
	FVE_KEYRING_ENH_PIN_INVALID = {
		.id = 0x6043
		.version = 0,
		.channel = 8,
		.level = 4,
		.opcode = 0,
		.task = 0,
		.keyword = 0x8000000000000000
	};
}
