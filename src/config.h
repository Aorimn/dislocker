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
#ifndef DISLOCKER_CFG_H
#define DISLOCKER_CFG_H


#include "xstd/xstdio.h"



/**
 * Different methods to decrypt the VMK
 */
typedef enum {
	USE_CLEAR_KEY         = (1 << 0),
	USE_USER_PASSWORD     = (1 << 1),
	USE_RECOVERY_PASSWORD = (1 << 2),
	USE_BEKFILE           = (1 << 3),
	USE_FVEKFILE          = (1 << 4)
} DECRYPT_MEAN;

/* Don't use this as a decryption mean, but as the last one */
#define LAST_MEAN (1 << 5)


/**
 * Just an enum not to have a random constant written everytime we use this
 */
enum {
	READ_ONLY = 1
};


/**
 * Structure containing command line options
 */
typedef struct _dis_cfg {
	/* BitLocker-volume-to-mount path */
	char*         volume_path;
	
	/* Which method to use to decrypt */
	DECRYPT_MEAN  decryption_mean;
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
	
	/* Output verbosity */
	LEVELS        verbosity;
	/* Output file */
	char*         log_file;
	
	/* Use this block of metadata and not another one (begin at 1) */
	unsigned char force_block;
	
	/*
	 * Begin to read the BitLocker volume at this offset, making this offset the
	 * zero-one
	 */
	off_t         offset;
	/* Mount the BitLocker volume in read-only mode */
	char          is_ro;
	/*
	 * By default, dislocker will check for unstable state that may corrupt data
	 * if mounted using fuse
	 */
	char          dont_check_state;
} dis_config_t;




/*
 * Function's prototypes
 */
void dis_usage();
int  dis_parse_args(dis_config_t* cfg, int argc, char** argv);
void dis_free_args(dis_config_t* cfg);
void dis_print_args(dis_config_t* cfg);



#endif /* DISLOCKER_CFG_H */
