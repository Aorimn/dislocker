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


#include "dislocker/xstd/xstdio.h"
#include <sys/types.h>
#include <unistd.h>



/**
 * Different methods to decrypt the VMK
 */
typedef enum {
	DIS_USE_CLEAR_KEY         = (1 << 0),
	DIS_USE_USER_PASSWORD     = (1 << 1),
	DIS_USE_RECOVERY_PASSWORD = (1 << 2),
	DIS_USE_BEKFILE           = (1 << 3),
	DIS_USE_FVEKFILE          = (1 << 4)
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


typedef enum {
	/* Below are options dis_getopts() can parse out of the command line */
	DIS_OPT_VOLUME_PATH = 1,
	DIS_OPT_CLEAR_KEY,
	DIS_OPT_BEK_FILE_PATH,
	DIS_OPT_RECOVERY_PASSWORD,
	DIS_OPT_USER_PASSWORD,
	DIS_OPT_FVEK_FILE_PATH,
	DIS_OPT_VERBOSITY,
	DIS_OPT_LOG_FILE_PATH,
	DIS_OPT_FORCE_BLOCK,
	DIS_OPT_VOLUME_OFFSET,
	DIS_OPT_READ_ONLY,
	DIS_OPT_DONT_CHECK_VOLUME_STATE,
	
	/* Below are options for users of the library (i.e: developers) */
	DIS_OPT_INITIALIZE_STATE
} dis_opt_e;




/**
 * dis_initialize() function does a lot of things. So, in order to provide
 * flexibility, place some kind of breakpoint after majors steps.
 */
typedef enum {
	DIS_STATE_COMPLETE_EVERYTHING = 0,
	DIS_STATE_AFTER_OPEN_VOLUME,
	DIS_STATE_AFTER_VOLUME_HEADER,
	DIS_STATE_AFTER_VOLUME_CHECK,
	DIS_STATE_AFTER_BITLOCKER_INFORMATION_CHECK,
	DIS_STATE_AFTER_VMK,
	DIS_STATE_AFTER_FVEK,
	DIS_STATE_BEFORE_DECRYPTION_CHECKING,
} dis_state_e;



#define checkupdate_dis_state(ctx, state)                       \
	do {                                                        \
		(ctx)->curr_state = (state);                            \
		if((state) == (ctx)->cfg.init_stop_at) {                \
			xprintf(L_DEBUG, "Exiting at state %d\n", (state)); \
			return (state);                                     \
		}                                                       \
	} while(0);




/**
 * Structure containing command line options
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
	/*
	 * Various flags one can use. See dis_flags_e enum above for possible values
	 */
	dis_flags_e   flags;
	
	/* Where dis_initialize() should stop */
	dis_state_e   init_stop_at;
} dis_config_t;




/*
 * Function's prototypes
 */
void dis_usage();
int  dis_getopts(dis_config_t* cfg, int argc, char** argv);
int  dis_setopt(dis_config_t* cfg, dis_opt_e opt_name, const void* opt_value);
void dis_free_args(dis_config_t* cfg);
void dis_print_args(dis_config_t* cfg);

int dis_is_read_only(dis_config_t* cfg);
int dis_is_volume_state_checked(dis_config_t* cfg);


#endif /* DISLOCKER_CFG_H */
