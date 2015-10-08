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
#ifndef COMMON_H
#define COMMON_H

/* Generic includes */
#include "dislocker/xstd/xstdio.h"
#include "dislocker/xstd/xstdlib.h"
#include <inttypes.h>
#include <stdint.h>
#include <string.h>



/* Convention */
#define TRUE 1
#define FALSE 0



/* Signatures of volumes */
#define BITLOCKER_SIGNATURE      "-FVE-FS-"
#define BITLOCKER_SIGNATURE_SIZE strlen(BITLOCKER_SIGNATURE)


#define NTFS_SIGNATURE           "NTFS    "
#define NTFS_SIGNATURE_SIZE      strlen(NTFS_SIGNATURE)


#define BITLOCKER_TO_GO_SIGNATURE "MSWIN4.1"
#define BITLOCKER_TO_GO_SIGNATURE_SIZE strlen(BITLOCKER_TO_GO_SIGNATURE)



#ifdef __ARCH_X86_64
# define F_OFF_T "tx"
#else
# define F_OFF_T "llx"
#endif /* __ARCH_X86_64 */

#define F_SIZE_T "zx"



/*
 * Prototypes of functions from common.c
 */
int dis_open(const char *file, int mode);
int dis_close(int fd);
ssize_t dis_read(int fd, void* buf, size_t count);
ssize_t dis_write(int fd, void* buf, size_t count);
off_t dis_lseek(int fd, off_t offset, int whence);

void hexdump(DIS_LOGS level, uint8_t* data, size_t data_size);

void xor_buffer(unsigned char* buf1, const unsigned char* buf2, unsigned char* output, size_t size);

void memclean(void* ptr, size_t size);



#ifdef _HAVE_RUBY
#include "dislocker/ruby.h"

VALUE rb_hexdump(uint8_t* data, size_t data_len);

#endif /* _HAVE_RUBY */

#endif // COMMON_H
