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
#ifndef DIS_CONFIG_PRIV_H
#define DIS_CONFIG_PRIV_H

#include "dislocker/config.h"


/**
 * Different methods to decrypt the VMK
 */
typedef enum {
	DIS_USE_CLEAR_KEY         = (1 << 0),
	DIS_USE_USER_PASSWORD     = (1 << 1),
	DIS_USE_RECOVERY_PASSWORD = (1 << 2),
	DIS_USE_BEKFILE           = (1 << 3),
	DIS_USE_FVEKFILE          = (1 << 4),
	DIS_USE_VMKFILE           = (1 << 8)
} DIS_DECRYPT_MEAN;

/* Don't use this as a decryption mean, but as the last one */
#define LAST_MEAN (1 << 5)


/**
 * Just an enum not to have a random constant written everytime we use this
 */
typedef enum {
	/* Make the volume read-only, in order not to corrupt it */
	DIS_FLAG_READ_ONLY               = (1 << 0),
	/*
	 * By default, dislocker will check for unstable state that may corrupt data
	 * if mounted using fuse
	 */
	DIS_FLAG_DONT_CHECK_VOLUME_STATE = (1 << 1),
} dis_flags_e;




/**
 * Structure containing options (command line ones and others if need be)
 */
typedef struct _dis_cfg {
	/* BitLocker-volume-to-mount path */
	char*         volume_path;

	/* Which method to use to decrypt */
	DIS_DECRYPT_MEAN  decryption_mean;
	/* Path to the .bek file in case of using the BEKFILE DECRYPT_MEAN */
	char*         bek_file;
	/*
	 * Recovery password to use in case of using the RECOVERY_PASSWORD
	 * DECRYPT_MEAN
	 */
	uint8_t*      recovery_password;
	/* User password to use in case of using the USER_PASSWORD DECRYPT_MEAN */
	uint8_t*      user_password;
	/* Use directly the FVEK file DECRYPT_MEAN */
	char*         fvek_file;
	/* Use directly the VMK file DECRYPT_MEAN */
	char*         vmk_file;

	/* Output verbosity */
	DIS_LOGS      verbosity;
	/* Output file */
	char*         log_file;

	/* Use this block of metadata and not another one (begin at 1) */
	unsigned char force_block;

	/*
	 * Begin to read the BitLocker volume at this offset, making this offset the
	 * zero-one
	 */
	off_t         offset;
	/*
	 * Various flags one can use. See dis_flags_e enum above for possible values
	 */
	dis_flags_e   flags;

	/* Where dis_initialize() should stop */
	dis_state_e   init_stop_at;
} dis_config_t;


#endif /* DIS_CONFIG_PRIV_H */
