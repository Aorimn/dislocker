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
#ifndef DISLOCKER_RETURN_VALUES_H
#define DISLOCKER_RETURN_VALUES_H

#include <errno.h>

/*
 * dislocker saves errno in this variable when returning something else than
 * DIS_RET_SUCCESS.
 * Returns (listed below) are for `high-level' errors, returned by dislocker,
 * whereas dis_errno is for `low-levels' ones, the reason why dislocker returned
 * an error.
 */
extern int dis_errno;


#define DIS_RET_SUCCESS 0
#define DIS_RET_ERROR_ALLOC -1
#define DIS_RET_ERROR_FILE_OPEN -2
#define DIS_RET_ERROR_FILE_CLOSE -3
#define DIS_RET_ERROR_FILE_READ -4
#define DIS_RET_ERROR_FILE_WRITE -5
#define DIS_RET_ERROR_FILE_SEEK -6

#define DIS_RET_ERROR_VOLUME_NOT_GIVEN -10
#define DIS_RET_ERROR_VOLUME_HEADER_READ -11
#define DIS_RET_ERROR_VOLUME_HEADER_CHECK -12
#define DIS_RET_ERROR_VOLUME_SIZE_NOT_FOUND -13
#define DIS_RET_ERROR_VOLUME_STATE_NOT_SAFE -14
#define DIS_RET_ERROR_VOLUME_READ_ONLY -15

#define DIS_RET_ERROR_METADATA_OFFSET -20
#define DIS_RET_ERROR_METADATA_CHECK -21
#define DIS_RET_ERROR_METADATA_VERSION_UNSUPPORTED -22
#define DIS_RET_ERROR_METADATA_FILE_SIZE_NOT_FOUND -23
#define DIS_RET_ERROR_METADATA_FILE_OVERWRITE -24
#define DIS_RET_ERROR_DATASET_CHECK -25
#define DIS_RET_ERROR_VMK_RETRIEVAL -26
#define DIS_RET_ERROR_FVEK_RETRIEVAL -27
#define DIS_RET_ERROR_VIRTUALIZATION_INFO_DATUM_NOT_FOUND -28

#define DIS_RET_ERROR_CRYPTO_INIT -40
#define DIS_RET_ERROR_CRYPTO_ALGORITHM_UNSUPPORTED -41

#define DIS_RET_ERROR_MUTEX_INIT -50
#define DIS_RET_ERROR_MUTEX_LOCK -51
#define DIS_RET_ERROR_MUTEX_UNLOCK -52

#define DIS_RET_ERROR_OFFSET_OUT_OF_BOUND -60

#define DIS_RET_ERROR_DISLOCKER_NOT_INITIALIZED -100
#define DIS_RET_ERROR_DISLOCKER_ENCRYPTION_ERROR -101
#define DIS_RET_ERROR_DISLOCKER_NO_WRITE_ON_METADATA -102
#define DIS_RET_ERROR_DISLOCKER_INVAL -103

#define DIS_RET_ERROR_RECOVERY_PASSWORD_EXTRACTION -110


#endif /* DISLOCKER_RETURN_VALUES_H */
