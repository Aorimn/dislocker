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
#ifndef EVENT_DESCRIPTORS_H
#define EVENT_DESCRIPTORS_H

#define UNUSED __attribute__ ((unused))


typedef struct {
	uint16_t id;
	uint8_t  version;
	uint8_t  channel;
	uint8_t  level;
	uint8_t  opcode;
	uint16_t task;
	uint64_t keyword;
} event_description_t;


/**
 * Available events
 */
UNUSED event_description_t FVE_ENCRYPT_START;
UNUSED event_description_t FVE_ENCRYPT_STOP;
UNUSED event_description_t FVE_ENCRYPT_COMPLETE;
UNUSED event_description_t FVE_DECRYPT_START;
UNUSED event_description_t FVE_DECRYPT_STOP;
UNUSED event_description_t FVE_DECRYPT_COMPLETE;
UNUSED event_description_t FVE_CONV_RESUME;
UNUSED event_description_t FVE_CONV_PAUSE;
UNUSED event_description_t FVE_AUTOUNLOCK_ENABLE_OK;
UNUSED event_description_t FVE_CONV_ERROR;
UNUSED event_description_t FVE_AUTOUNLOCK_DISABLE_OK;
UNUSED event_description_t FVE_CONV_SECTOR_ERROR;
UNUSED event_description_t FVE_AUTOUNLOCK_ENABLE_ERROR;
UNUSED event_description_t FVE_AUTOUNLOCK_DISABLE_ERROR;
UNUSED event_description_t FVE_AUTOUNLOCK_ERROR;
UNUSED event_description_t FVE_CONV_AUTO_START_FAILURE;
UNUSED event_description_t FVE_METADATA_DISK_FAILED_WRITE_ERROR;
UNUSED event_description_t FVE_METADATA_REBUILD_DATA_LOSS_ERROR;
UNUSED event_description_t FVE_CONV_BAD_CLUSTERS_SKIPPED;
UNUSED event_description_t FVE_KEYRING_INVALID_CONFIG;
UNUSED event_description_t FVE_KEYRING_KEY_UNAVAILABLE;
UNUSED event_description_t FVE_METADATA_PARTIAL_COMMIT;
UNUSED event_description_t FVE_METADATA_FAILED_COMMIT;
UNUSED event_description_t FVE_METADATA_DISK_FAILED_FLUSH_ERROR;
UNUSED event_description_t FVE_METADATA_DISK_FAILED_READBACK_ERROR;
UNUSED event_description_t FVE_METADATA_DISK_FAILED_VERIFY_ERROR;
UNUSED event_description_t FVE_METADATA_CORRUPT_ERROR;
UNUSED event_description_t FVE_METADATA_FAILOVER_ERROR;
UNUSED event_description_t FVE_METADATA_FAILOVER;
UNUSED event_description_t FVE_METADATA_SUBSET;
UNUSED event_description_t FVE_METADATA_REBUILD_DROP;
UNUSED event_description_t FVE_INIT_FAILED_ERROR;
UNUSED event_description_t FVE_CONV_RECOVERING;
UNUSED event_description_t FVE_MOR_BIT_RUN_INIT_ERROR;
UNUSED event_description_t FVE_MOR_BIT_SET_ERROR;
UNUSED event_description_t FVE_KEYRING_KEY_OBTAINED;
UNUSED event_description_t FVE_AUTOUNLOCK_NO_MASTER_KEY;
UNUSED event_description_t FVE_KEYRING_DEBUGGER_ENABLED;
UNUSED event_description_t FVE_KEYRING_BAD_PARTITION_SIZE;
UNUSED event_description_t FVE_KEYRING_MOR_FAILED;
UNUSED event_description_t FVE_KEYRING_KEYFILE_NOT_FOUND;
UNUSED event_description_t FVE_KEYRING_KEYFILE_CORRUPT;
UNUSED event_description_t FVE_KEYRING_KEYFILE_NO_VMK;
UNUSED event_description_t FVE_KEYRING_TPM_DISABLED;
UNUSED event_description_t FVE_KEYRING_TPM_INVALID_SRK;
UNUSED event_description_t FVE_KEYRING_TPM_INVALID_PCR;
UNUSED event_description_t FVE_KEYRING_TPM_NO_VMK;
UNUSED event_description_t FVE_KEYRING_INVALID_APPLICATION;
UNUSED event_description_t FVE_KEYRING_PIN_INVALID;
UNUSED event_description_t FVE_KEYRING_PASSWORD_INVALID;
UNUSED event_description_t FVE_KEYRING_GOT_KEY;
UNUSED event_description_t FVE_KEYRING_UNEXPECTED;
UNUSED event_description_t FVE_KEYRING_ENH_PIN_INVALID;





#endif /* EVENT_DESCRIPTORS_H */
