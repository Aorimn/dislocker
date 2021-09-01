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


#include "dislocker/xstd/xstdlib.h"
#include "dislocker/xstd/xstdio.h"



/**
 * malloc wrapper
 *
 * @param size The size of the memory to allocate
 * @return A pointer to the memory
 */
void* dis_malloc(size_t size)
{
	if(size == 0)
	{
		dis_printf(L_CRITICAL, "malloc(0) is not accepted, aborting\n");
		exit(2);
	}
	void* p = malloc(size);

	dis_printf(L_DEBUG, "New memory allocation at %p (%#zx bytes allocated)\n", p, size);

	if(p == NULL)
	{
		dis_printf(L_CRITICAL, "Cannot allocate more memory, aborting\n");
		exit(2);
	}

	return p;
}


/**
 * free wrapper
 *
 * @param pointer The pointer to the memory to free
 */
void dis_free(void *pointer)
{
	dis_printf(L_DEBUG, "Freeing pointer at address %p\n", pointer);

	free(pointer);
}
