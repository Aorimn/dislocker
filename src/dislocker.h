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
#ifndef DISLOCKER_MAIN_H
#define DISLOCKER_MAIN_H

#include <stdint.h>

#include "config.h"
#include "encommon.h"



/**
 * dis_initialize() function does a lot of things. So, in order to provide
 * flexibility, place some kind of breakpoint after majors steps.
 */
typedef enum {
	COMPLETE_EVERYTHING = 0,
	AFTER_OPEN_VOLUME,
	AFTER_VOLUME_HEADER,
	AFTER_VOLUME_CHECK,
	AFTER_BITLOCKER_INFORMATION,
	AFTER_BITLOCKER_INFORMATION_CHECK,
	AFTER_VMK,
	AFTER_FVEK,
	BEFORE_DECRYPTION_CHECKING,
} dis_state_e;


#define checkupdate_dis_state(ctx, state)                       \
	do {                                                        \
		(ctx)->curr_state = (state);                            \
		if((state) == (ctx)->stop_at) {                         \
			xprintf(L_DEBUG, "Exiting at state %d\n", (state)); \
			return EXIT_SUCCESS;                                \
		}                                                       \
	} while(0);


/**
 * Main structure to pass to dislocker functions. These keeps various
 * information in it.
 */
typedef struct _dis_ctx {
	/*
	 * Dislocker's configuration.
	 * Note that there's the dis_parse_args() function to fill this structure.
	 */
	dis_config_t cfg;
	
	/*
	 * Structure needed for dec/encryption processes.
	 */
	dis_iodata_t io_data;
	
	/*
	 * States dislocker initialisation is at or will be stopped at.
	 */
	dis_state_e curr_state;
	dis_state_e stop_at;
} dis_context_t;



/**
 * Public prototypes
 */

/**
 * Initialize dislocker. As stated above, the initialisation process may be
 * stopped at any major step in order to retrieve different information. Note
 * that you have to provide an already allocated dis_ctx with an already filled
 * dis_ctx->cfg with parameters for dislocker to initialize correctly.
 * This function malloc(3)s structures, see dis_destroy() below for free(3)ing
 * it.
 * dislock() & enlock() function may not be called before executing this
 * function.
 * 
 * @param dis_ctx The dislocker context needed for all operations. As stated
 * above, this parameter has to be pre-allocated. Furthermore, the dis_ctx->cfg
 * structure has to be filled with parameters to properly initialize dislocker.
 */
int dis_initialize(dis_context_t* dis_ctx);

/**
 * Once dis_initialize() has been called, this function is able to decrypt the
 * BitLocker-encrypted volume.
 * 
 * @param dis_ctx The same parameter passed to dis_initialize.
 * @param offset The offset from where to start decrypting.
 * @param buffer The buffer to put decrypted data to.
 * @param size The size of a region to decrypt.
 */
int dislock(dis_context_t* dis_ctx, uint8_t* buffer, off_t offset, size_t size);

/**
 * Once dis_initialize() has been called, this function is able to encrypt data
 * to the BitLocker-encrypted volume.
 * 
 * @param dis_ctx The same parameter passed to dis_initialize.
 * @param offset The offset where to put the data.
 * @param buffer The buffer from where to take data to encrypt.
 * @param size The size of a region to decrypt.
 */
int enlock(dis_context_t* dis_ctx, uint8_t* buffer, off_t offset, size_t size);

/**
 * Destroy dislocker structures. This is important to call this function after
 * dislocker is not needed -- if dis_initialize() has been called -- in order
 * for dislocker to free(3) the used memory.
 * dislock() & enlock() functions may not be called anymore after executing this
 * function.
 */
int dis_destroy(dis_context_t* dis_ctx);


#endif /* DISLOCKER_MAIN_H */

