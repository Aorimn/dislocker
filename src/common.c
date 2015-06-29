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

#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dislocker/return_values.h"
#include "dislocker/common.h"

/**
 * Here are wrappers for low-level and common used functions
 * These check the return value and print debug info if needed
 */


/**
 * open syscall wrapper
 *
 * @param file The file (with its path) to open
 * @param flags The mode(s) along the opening (read/write/...)
 * @return The file descriptor returned by the actual open
 */
#define DIS_XOPEN_ARBITRARY_VALUE 42
#define DIS_XOPEN_FAIL_STR "Failed to open file"
#define DIS_XOPEN_FAIL_LEN sizeof(DIS_XOPEN_FAIL_STR)
int dis_open(const char* file, int flags)
{
	int fd = -1;

	dis_printf(L_DEBUG, "Trying to open '%s'...\n", file);

	if((fd = open(file, flags)) < 0)
	{
		char err_string[DIS_XOPEN_FAIL_LEN + DIS_XOPEN_ARBITRARY_VALUE + 4] = {0,};
		char file_truncated[DIS_XOPEN_ARBITRARY_VALUE] = {0,};

		dis_errno = errno;

		snprintf(file_truncated, DIS_XOPEN_ARBITRARY_VALUE, "%s", file);

		if(DIS_XOPEN_ARBITRARY_VALUE < strlen(file))
		{
			file_truncated[DIS_XOPEN_ARBITRARY_VALUE-4] = '.';
			file_truncated[DIS_XOPEN_ARBITRARY_VALUE-3] = '.';
			file_truncated[DIS_XOPEN_ARBITRARY_VALUE-2] = '.';
		}

		snprintf(
			err_string,
			DIS_XOPEN_FAIL_LEN + DIS_XOPEN_ARBITRARY_VALUE + 4,
			DIS_XOPEN_FAIL_STR " '%s'",
			file_truncated
		);

		dis_printf(L_ERROR, "%s: %s\n", err_string, strerror(dis_errno));
		return -1;
	}

	dis_printf(L_DEBUG, "Opened (fd #%d).\n", fd);

	return fd;
}


/**
 * close syscall wrapper
 *
 * @param fd The result of an dis_open call
 * @return The result of the close call
 */
#define DIS_XCLOSE_FAIL_STR "Failed to close previously opened stream"
#define DIS_XCLOSE_FAIL_LEN sizeof(DIS_XCLOSE_FAIL_STR)
int dis_close(int fd)
{
	int res = -1;

	dis_printf(L_DEBUG, "Trying to close fd #%d...\n", fd);

	if((res = close(fd)) < 0)
	{
		dis_errno = errno;
		dis_printf(L_ERROR, DIS_XCLOSE_FAIL_STR " #%d: %s\n", fd, strerror(errno));
	}

	return res;
}


/**
 * read syscall wrapper
 *
 * @param fd The file to read from
 * @param buf The buffer where to put read data
 * @param count The number of bytes to read
 * @return The number of bytes read
 */
#define DIS_XREAD_FAIL_STR "Failed to read in"
#define DIS_XREAD_FAIL_LEN sizeof(DIS_XREAD_FAIL_STR)
ssize_t dis_read(int fd, void* buf, size_t count)
{
	ssize_t res = -1;

#ifdef __ARCH_X86_64
	dis_printf(L_DEBUG, "Reading %lu bytes from #%d into %p\n", count, fd, buf);
#else
	dis_printf(L_DEBUG, "Reading %u bytes from #%d into %p\n", count, fd, buf);
#endif /* __ARCH_X86_64 */

	if((res = read(fd, buf, count)) < 0)
	{
		dis_errno = errno;
		dis_printf(L_ERROR, DIS_XREAD_FAIL_STR " #%d: %s\n", fd, strerror(errno));
	}

	return res;
}


/**
 * write syscall wrapper
 *
 * @param fd The file to write to
 * @param buf The buffer where to put data
 * @param count The number of bytes to write
 * @return The number of bytes written
 */
#define DIS_XWRITE_FAIL_STR "Failed to write in"
#define DIS_XWRITE_FAIL_LEN sizeof(DIS_XWRITE_FAIL_STR)
ssize_t dis_write(int fd, void* buf, size_t count)
{
	ssize_t res = -1;

#ifdef __ARCH_X86_64
	dis_printf(L_DEBUG, "Writing %lu bytes to #%d from %p\n", count, fd, buf);
#else
	dis_printf(L_DEBUG, "Writing %u bytes to #%d from %p\n", count, fd, buf);
#endif /* __ARCH_X86_64 */

	if((res = write(fd, buf, count)) < 0)
	{
		dis_errno = errno;
		dis_printf(L_ERROR, DIS_XWRITE_FAIL_STR " #%d: %s\n", fd, strerror(errno));
	}

	return res;
}


/**
 * lseek syscall wrapper
 *
 * @param fd Move cursor of this file descriptor
 * @param offset To this offset
 * @param whence  According to this whence
 * @return The result of the lseek call
 */
#define DIS_XSEEK_FAIL_STR "Failed to seek in"
#define DIS_XSEEK_FAIL_LEN sizeof(DIS_XSEEK_FAIL_STR)
off_t dis_lseek(int fd, off_t offset, int whence)
{
	off_t res = -1;

	dis_printf(L_DEBUG, "Positionnong #%d at offset %lld from %d\n", fd, offset, whence);

	if((res = lseek(fd, offset, whence)) < 0)
	{
		dis_errno = errno;
		dis_printf(L_ERROR, DIS_XSEEK_FAIL_STR " #%d: %s\n", fd, strerror(errno));
	}

	return res;
}


/**
 * Print data in hexa
 *
 * @param data Data to print
 * @param data_len Length of the data to print
 */
void hexdump(DIS_LOGS level, uint8_t* data, size_t data_len)
{
	size_t i, j, max = 0;
	size_t offset = 16;

	for(i = 0; i < data_len; i += offset)
	{
		char s[512] = {0,};

		snprintf(s, 12, "0x%.8zx ", i);
		max = (i+offset > data_len ? data_len : i + offset);

		for(j = i; j < max; j++)
			snprintf(&s[11 + 3*(j-i)], 4, "%.2x%s", data[j], (j-i == offset/2-1 && j+1 != max) ? "-" : " ");

		dis_printf(level, "%s\n", s);
	}
}


/**
 * Apply a bitwise-xor on two buffers
 *
 * @param buf1 The first buffer to xor
 * @param buf2 The second buffer to xor
 * @param size The size of the two buffers
 * @param output The resulted xored output (the result is put into buf1 if no output buffer is given)
 */
void xor_buffer(unsigned char* buf1, const unsigned char* buf2, unsigned char* output, size_t size)
{
	size_t loop;
	unsigned char* tmp = NULL;

	if(output)
		tmp = output;
	else
		tmp = buf1;

	for(loop = 0; loop < size; ++loop, ++buf1, ++buf2, ++tmp)
		*tmp = *buf1 ^ *buf2;
}


/**
 * Clean memory before freeing
 *
 * @param ptr A pointeur to the memory region
 * @param size The size of the region
 */
void memclean(void* ptr, size_t size)
{
	memset(ptr, 0, size);
	dis_free(ptr);
}


