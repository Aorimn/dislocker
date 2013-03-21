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

#include "common.h"

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
int xopen(const char* file, int flags)
{
	int fd = -1;
	
	xprintf(L_DEBUG, "Trying to open '%s'...\n", file);
	
	if((fd = open(file, flags)) < 0)
	{
		char* err_string = NULL;
		size_t arbitrary_value = 42;
		char* before = "Failed to open file";
		char* after = xmalloc(arbitrary_value);
		
		snprintf(after, arbitrary_value, "%s", file);
		
		if(arbitrary_value < strlen(file))
		{
			after[arbitrary_value-4] = '.';
			after[arbitrary_value-3] = '.';
			after[arbitrary_value-2] = '.';
		}
		
		size_t len = strlen(before);
		
		err_string = xmalloc(len + arbitrary_value + 4);
		snprintf(err_string, len + arbitrary_value + 4, "%s '%s'", before, after);
		
		xfree(after);
		
		xperror(err_string);
	}
	
	xprintf(L_DEBUG, "Opened (fd #%d).\n", fd);
	
	return fd;
}


/**
 * open syscall wrapper (for the one with mode)
 * 
 * @param file The file (with its path) to open
 * @param flags The mode(s) along the opening (read/write/...)
 * @param mode The mode(s) a file will have if created
 * @return The file descriptor returned by the actual open
 */
int xopen2(const char* file, int flags, mode_t mode)
{
	int fd = -1;
	
	xprintf(L_DEBUG, "Trying to open '%s'... ", file);
	
	if((fd = open(file, flags, mode)) < 0)
	{
		char* err_string = NULL;
		size_t arbitrary_value = 42;
		char* before = "Failed to open file";
		char* after = xmalloc(arbitrary_value);
		
		snprintf(after, arbitrary_value, "%s", file);
		
		if(arbitrary_value < strlen(file))
		{
			after[arbitrary_value-4] = '.';
			after[arbitrary_value-3] = '.';
			after[arbitrary_value-2] = '.';
		}
		
		size_t len = strlen(before);
		
		err_string = xmalloc(len + arbitrary_value + 4);
		snprintf(err_string, len + arbitrary_value + 4, "%s '%s'", before, after);
		
		xfree(after);
		
		xperror(err_string);
	}
	
	xprintf(L_DEBUG, "Opened (fd #%d).\n", fd);
	
	return fd;
}


/**
 * close syscall wrapper
 * 
 * @param fd The result of an xopen call
 * @return The result of the close call
 */
int xclose(int fd)
{
	int res = -1;
	
	xprintf(L_DEBUG, "Trying to close fd #%d...\n", fd);
	
	if((res = close(fd)) < 0)
	{
		char* err_string = NULL;
		char* before = "Failed to close previously opened stream";
		
		size_t len = strlen(before) + 1;
		
		err_string = xmalloc(len + 4);
		snprintf(err_string, len + 4, "%s #%d", before, fd);
		
		xperror(err_string);
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
ssize_t xread(int fd, void* buf, size_t count)
{
	ssize_t res = -1;
	
#ifdef __ARCH_X86_64
	xprintf(L_DEBUG, "Reading %lu bytes from #%d into %p\n", count, fd, buf);
#else
	xprintf(L_DEBUG, "Reading %u bytes from #%d into %p\n", count, fd, buf);
#endif /* __ARCH_X86_64 */
	
	if((res = read(fd, buf, count)) < 0)
	{
		char* err_string = NULL;
		char* before = "Failed to read in";
		
		size_t len = strlen(before) + 1;
		
		err_string = xmalloc(len + 4);
		snprintf(err_string, len + 4, "%s #%d", before, fd);
		
		xperror(err_string);
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
ssize_t xwrite(int fd, void* buf, size_t count)
{
	ssize_t res = -1;
	
#ifdef __ARCH_X86_64
	xprintf(L_DEBUG, "Writing %lu bytes to #%d from %p\n", count, fd, buf);
#else
	xprintf(L_DEBUG, "Writing %u bytes to #%d from %p\n", count, fd, buf);
#endif /* __ARCH_X86_64 */
	
	if((res = write(fd, buf, count)) < 0)
	{
		char* err_string = NULL;
		char* before = "Failed to write in";
		
		size_t len = strlen(before) + 1;
		
		err_string = xmalloc(len + 4);
		snprintf(err_string, len + 4, "%s #%d", before, fd);
		
		xperror(err_string);
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
off_t xlseek(int fd, off_t offset, int whence)
{
	off_t res = -1;
	
	xprintf(L_DEBUG, "Positionnong #%d at offset %lld from %d\n", fd, offset, whence);
	
	if((res = lseek(fd, offset, whence)) < 0)
	{
		char* err_string = NULL;
		char* before = "Failed to seek in";
		
		size_t len = strlen(before);
		
		err_string = xmalloc(len + 4);
		snprintf(err_string, len + 4, "%s #%d", before, fd);
		
		xperror(err_string);
	}
	
	return res;
}


/**
 * Print data in hexa
 * 
 * @param data Data to print
 * @param data_len Length of the data to print
 */
void hexdump(LEVELS level, uint8_t* data, size_t data_len)
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
		
		xprintf(level, "%s\n", s);
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
	xfree(ptr);
}


