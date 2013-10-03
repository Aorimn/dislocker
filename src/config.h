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
	USE_CLEAR_KEY         = 0x01,
	USE_USER_PASSWORD     = 0x02,
	USE_RECOVERY_PASSWORD = 0x04,
	USE_BEKFILE           = 0x08,
	USE_FVEKFILE          = 0x10
} DECRYPT_MEAN;


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
} dis_config_t;




/*
 * Function's prototypes
 */
void usage();
int  parse_args(dis_config_t* cfg, int argc, char** argv);
void free_args (dis_config_t* cfg);
void print_args(dis_config_t* cfg);



#endif /* DISLOCKER_CFG_H */
