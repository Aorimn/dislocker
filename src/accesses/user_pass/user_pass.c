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
#if defined(__FREEBSD)
#  define _WITH_GETLINE
#endif /* __FREEBSD */

#include "user_pass.h"

#include <termios.h>
#include <stdio.h>



/**
 * Get the user's pass without displaying it.
 *
 * @param lineptr A pointer to a malloc()-able variable where the password will
 * be
 * @param stream The FILE* from which to get the password
 * @return The number of bytes read
 */
static ssize_t my_getpass(char **lineptr, FILE *stream)
{
	if(!lineptr || !stream)
		return -1;

	size_t n = 0;
	ssize_t nread;

	/*
	 * If we're running tests under check, disable echoing off: this doesn't
	 * work on pipes
	 */
#ifndef __CK_DOING_TESTS
	struct termios old, new;

	/* Turn echoing off and fail if we can't. */
	if(tcgetattr(fileno(stream), &old) != 0)
		return -1;

	new = old;
	new.c_lflag &= (tcflag_t)~ECHO;
	if(tcsetattr(fileno(stream), TCSAFLUSH, &new) != 0)
		return -1;
#endif

	/* Read the password. */
	nread = getline(lineptr, &n, stream);
	xprintf(L_DEBUG, "New memory allocation at %p (%#" F_SIZE_T " byte allocated)\n", (void*)*lineptr, n);

#ifndef __CK_DOING_TESTS
	/* Restore terminal. */
	(void) tcsetattr(fileno(stream), TCSAFLUSH, &old);
#endif

	return nread;
}


/**
 * Compute the user hash from a user password using the stretch algorithm.
 *
 * @param user_password The raw user password that we have to calculate the hash
 * @param salt The salt used for crypto (16 bytes)
 * @param result_key Will contain the resulting hash key (32 bytes)
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int user_key(const uint8_t *user_password,
             const uint8_t *salt,
             uint8_t *result_key)
{
	if(!user_password || !salt || !result_key)
	{
		xprintf(L_ERROR, "Invalid parameter given to user_key().\n");
		return FALSE;
	}


	uint16_t* utf16_password = NULL;
	size_t    utf16_length   = 0;
	uint8_t   user_hash[32]  = {0,};

	/*
	 * We first get the SHA256(SHA256(to_UTF16(user_password)))
	 */
	utf16_length   = (strlen((char*)user_password)+1) * sizeof(uint16_t);
	utf16_password = xmalloc(utf16_length);

	if(!asciitoutf16(user_password, utf16_password))
	{
		xprintf(L_ERROR, "Can't convert user password to UTF-16, aborting.\n");
		memclean(utf16_password, utf16_length);
		return FALSE;
	}

	xprintf(L_DEBUG, "UTF-16 user password:\n");
	hexdump(L_DEBUG, (uint8_t*)utf16_password, utf16_length);

	/* We're not taking the '\0\0' end of the UTF-16 string */
	SHA256((unsigned char *)utf16_password, utf16_length-2, user_hash);
	SHA256((unsigned char *)user_hash,      32,           user_hash);

	/*
	 * We then pass it to the key stretching manipulation
	 */
	if(!stretch_user_key(user_hash, (uint8_t *)salt, result_key))
	{
		xprintf(L_ERROR, "Can't stretch the user password, aborting.\n");
		memclean(utf16_password, utf16_length);
		return FALSE;
	}

	memclean(utf16_password, utf16_length);

	return TRUE;
}


/**
 * Prompt for the user password to be entered
 *
 * @param up The place where to put the entered user password
 * @return TRUE if up can be trusted, FALSE otherwise
 */
int prompt_up(uint8_t** up)
{
	// Check the parameter
	if(!up)
		return FALSE;

	/* There's no need for a prompt if we're doing tests */
#ifndef __CK_DOING_TESTS
	printf("Enter the user password: ");
	fflush(NULL);
#endif

	*up = NULL;

	ssize_t nb_read = my_getpass((char**)up, stdin);

	if(nb_read <= 0)
	{
		if(*up)
			xfree(*up);
		*up = NULL;
		xprintf(L_ERROR, "Can't get a user password using getline()\n");
		return FALSE;
	}

	// getline() gets the '\n' character, so we need to remove it
	chomp((char*)*up);

	return TRUE;
}
