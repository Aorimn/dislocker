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
#ifndef DIS_DISLOCKER_PRIV_H
#define DIS_DISLOCKER_PRIV_H

#include <stdint.h>

#include "dislocker/dislocker.h"
#include "dislocker/config.priv.h"
#include "dislocker/inouts/inouts.priv.h"
#include "dislocker/metadata/metadata.priv.h"



#include "dislocker/return_values.h"
#define checkupdate_dis_state(ctx, state)                                   \
	do {                                                                    \
		(ctx)->curr_state = (state);                                        \
		if((state) == (ctx)->cfg.init_stop_at) {                            \
			dis_printf(L_DEBUG, "Library end init at state %d\n", (state)); \
			return (state);                                                 \
		}                                                                   \
	} while(0);



/**
 * Main structure to pass to dislocker functions. These keeps various
 * information in it.
 */
struct _dis_ctx {
	/*
	 * Dislocker's configuration.
	 * Note that there's the dis_getopts() function to fill this structure from
	 * command-line's arguments and the dis_setopt() function
	 */
	dis_config_t cfg;

	/*
	 * Structure to keep volume metadata around.
	 */
	dis_metadata_t metadata;

	/*
	 * Structure needed for dec/encryption processes.
	 */
	dis_iodata_t io_data;

	/*
	 * States dislocker initialisation is at or will be stopped at.
	 */
	dis_state_e curr_state;

	/* The file descriptor to the encrypted volume */
	int fve_fd;
};



#ifdef _HAVE_RUBY

enum {
	DIS_RB_CLASS_DISLOCKER = 0,
	DIS_RB_CLASS_METADATA,
	DIS_RB_CLASS_DATUM,
	DIS_RB_CLASS_ACCESSES,
	DIS_RB_CLASS_MAX
};

#endif /* _HAVE_RUBY */


#endif /* DIS_DISLOCKER_PRIV_H */
