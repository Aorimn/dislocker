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
#include <sys/types.h>
#include "dislocker/xstd/xstdio.h" // Only for off_t



/**
 * Main structure to pass to dislocker functions. These keeps various
 * information in it.
 */
typedef struct _dis_ctx* dis_context_t;



/**
 * Public prototypes
 */
/**
 * Allocate internal structure, named a context here. This structure is to be
 * passed to this API's functions and records internal state.
 */
dis_context_t dis_new();

/**
 * Initialize dislocker. As stated above, the initialisation process may be
 * stopped at any major step in order to retrieve different information. Note
 * that you have to provide an already allocated dis_ctx (through the use of the
 * dis_new() function).
 * This function malloc(3)s structures, see dis_destroy() below for free(3)ing
 * it. If you're weary of memory leaks, you'll make sure to call dis_destroy()
 * to free the dis_new()-allocated context.
 * dislock() & enlock() function may not be called before executing this
 * function - or at least they won't work.
 *
 * @param dis_ctx The dislocker context needed for all operations. As stated
 * above, this parameter has to be pre-allocated through the use of the
 * dis_new() function.
 */
int dis_initialize(dis_context_t dis_ctx);

/**
 * Once dis_initialize() has been called, this function is able to decrypt the
 * BitLocker-encrypted volume.
 *
 * @param dis_ctx The same parameter passed to dis_initialize.
 * @param offset The offset from where to start decrypting.
 * @param buffer The buffer to put decrypted data to.
 * @param size The size of a region to decrypt.
 */
int dislock(dis_context_t dis_ctx, uint8_t* buffer, off_t offset, size_t size);

/**
 * Once dis_initialize() has been called, this function is able to encrypt data
 * to the BitLocker-encrypted volume.
 *
 * @param dis_ctx The same parameter passed to dis_initialize.
 * @param offset The offset where to put the data.
 * @param buffer The buffer from where to take data to encrypt.
 * @param size The size of a region to decrypt.
 */
int enlock(dis_context_t dis_ctx, uint8_t* buffer, off_t offset, size_t size);

/**
 * Destroy dislocker structures. This is important to call this function after
 * dislocker is not needed -- if dis_initialize() has been called -- in order
 * for dislocker to free(3) the used memory.
 * dislock() & enlock() functions may not be called anymore after executing this
 * function.
 */
int dis_destroy(dis_context_t dis_ctx);

/**
 * Retrieve the fd for the FVE volume. This permits reading/writing - although
 * not encouraged - directly to the volume.
 */
int get_fvevol_fd(dis_context_t dis_ctx);

/**
 * Retrieve the recovery password from the VMK.
 * This function requires the VMK to have been successfully decrypted
 * (i.e., dis_initialize() must have been called with a valid decryption method
 * and reached at least the DIS_STATE_AFTER_VMK state).
 *
 * @param dis_ctx The dislocker context with a decrypted VMK
 * @param password Output buffer for the recovery password. Must be at least 56
 * bytes (8 groups of 6 digits, 7 dashes, plus null terminator).
 * @return DIS_RET_SUCCESS on success, or an error code on failure
 */
int dis_get_recovery_password(dis_context_t dis_ctx, char* password);


#endif /* DISLOCKER_MAIN_H */
