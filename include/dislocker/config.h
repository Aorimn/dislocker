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


#include <sys/types.h>
#include "dislocker/dislocker.h"




typedef enum {
	/* Below are options dis_getopts() can parse out of the command line */
	DIS_OPT_VOLUME_PATH = 1,
	DIS_OPT_USE_CLEAR_KEY,
	DIS_OPT_USE_BEK_FILE,
	DIS_OPT_SET_BEK_FILE_PATH,
	DIS_OPT_USE_RECOVERY_PASSWORD,
	DIS_OPT_SET_RECOVERY_PASSWORD,
	DIS_OPT_USE_USER_PASSWORD,
	DIS_OPT_SET_USER_PASSWORD,
	DIS_OPT_USE_FVEK_FILE,
	DIS_OPT_SET_FVEK_FILE_PATH,
	DIS_OPT_USE_VMK_FILE,
	DIS_OPT_SET_VMK_FILE_PATH,
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


/*
 * Function's prototypes
 */
void dis_usage();
int  dis_getopts(dis_context_t dis_ctx, int argc, char** argv);

int  dis_getopt(dis_context_t dis_ctx, dis_opt_e opt_name, void** opt_value);
int  dis_setopt(dis_context_t dis_ctx, dis_opt_e opt_name, const void* opt_value);
void dis_free_args(dis_context_t dis_ctx);
void dis_print_args(dis_context_t dis_ctx);

int dis_is_read_only(dis_context_t dis_ctx);
int dis_is_volume_state_checked(dis_context_t dis_ctx);


#endif /* DISLOCKER_CFG_H */
