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

#include "dislocker/accesses/user_pass/user_pass.h"
#include "dislocker/metadata/vmk.h"

#include <termios.h>
#include <stdio.h>
#include <unistd.h>


/**
 * Get the VMK datum using a user password
 *
 * @param dataset The dataset of BitLocker's metadata on the volume
 * @param cfg The configuration structure
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_user_pass(dis_metadata_t dis_meta,
                           dis_config_t* cfg,
                           void** vmk_datum)
{
	return get_vmk_from_user_pass2(dis_meta, &cfg->user_password, vmk_datum);
}


/**
 * Get the VMK datum using a user password
 *
 * @param dataset The dataset of BitLocker's metadata on the volume
 * @param user_password The user password provided
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_user_pass2(dis_metadata_t dis_meta,
                            uint8_t** user_password,
                            void** vmk_datum)
{
	// Check parameters
	if(!dis_meta || !user_password)
		return FALSE;

	uint8_t user_hash[32] = {0,};
	uint8_t salt[16]      = {0,};

	/* If the user password wasn't provide, ask for it */
	if(!*user_password)
		if(!prompt_up(user_password))
		{
			dis_printf(L_ERROR, "Cannot get valid user password. Abort.\n");
			return FALSE;
		}

	dis_printf(
		L_DEBUG,
		"Using the user password: '%s'.\n",
		(char *) *user_password
	);


	/*
	 * We need a salt contained in the VMK datum associated to the recovery
	 * password, so go get this salt and the VMK datum first
	 * We use here the range which should be equal to 0x2000
	 * There may be another mean to find the correct datum, but I don't see
	 * another one here
	 */
	if(!get_vmk_datum_from_range(dis_meta, 0x2000, 0x2000, (void**) vmk_datum, NULL))
	{
		dis_printf(
			L_ERROR,
			"Error, can't find a valid and matching VMK datum. Abort.\n"
		);
		*vmk_datum = NULL;
		memclean((char*) *user_password, strlen((char*) *user_password));
		*user_password = NULL;
		return FALSE;
	}


	/*
	 * We have the datum containing other data, so get in there and take the
	 * nested one with type 3 (stretch key)
	 */
	void* stretch_datum = NULL;
	if(!get_nested_datumvaluetype(
			*vmk_datum,
			DATUMS_VALUE_STRETCH_KEY,
			&stretch_datum
		) ||
	   !stretch_datum)
	{
		char* type_str = datumvaluetypestr(DATUMS_VALUE_STRETCH_KEY);
		dis_printf(
			L_ERROR,
			"Error looking for the nested datum of type %hd (%s) in the VMK one"
			". Internal failure, abort.\n",
			DATUMS_VALUE_STRETCH_KEY,
			type_str
		);
		dis_free(type_str);
		*vmk_datum = NULL;
		memclean( (char*) *user_password, strlen((char*) *user_password));
		*user_password = NULL;
		return FALSE;
	}


	/* The salt is in here, don't forget to keep it somewhere! */
	memcpy(salt, ((datum_stretch_key_t*) stretch_datum)->salt, 16);


	/* Get data which can be decrypted with this password */
	void* aesccm_datum = NULL;
	if(!get_nested_datumvaluetype(
			*vmk_datum,
			DATUMS_VALUE_AES_CCM,
			&aesccm_datum
		) ||
	   !aesccm_datum)
	{
		dis_printf(
			L_ERROR,
			"Error finding the AES_CCM datum including the VMK. "
			"Internal failure, abort.\n"
		);
		*vmk_datum = NULL;
		memclean((char*) *user_password, strlen((char*) *user_password));
		*user_password = NULL;
		return FALSE;
	}


	/*
	 * We have all the things we need to compute the intermediate key from
	 * the user password, so do it!
	 */
	if(!user_key(*user_password, salt, user_hash))
	{
		dis_printf(L_CRITICAL, "Can't stretch the user password, aborting.\n");
		*vmk_datum = NULL;
		memclean((char*) *user_password, strlen((char*) *user_password));
		*user_password = NULL;
		return FALSE;
	}

	/* As the computed key length is always the same, use a direct value */
	return get_vmk(
		(datum_aes_ccm_t*) aesccm_datum,
		user_hash,
		32,
		(datum_key_t**) vmk_datum
	);
}


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

	if(isatty(fileno(stream)))
	{
		/* Turn echoing off and fail if we can't. */
		if(tcgetattr(fileno(stream), &old) != 0)
			return -1;

		new = old;
		new.c_lflag &= (tcflag_t)~ECHO;
		if(tcsetattr(fileno(stream), TCSAFLUSH, &new) != 0)
			return -1;
	}
#endif /* __CK_DOING_TESTS */

	/* Read the password. */
	nread = getline(lineptr, &n, stream);

#ifndef __CK_DOING_TESTS
	if(isatty(fileno(stream)))
	{
		/* Restore terminal. */
		(void) tcsetattr(fileno(stream), TCSAFLUSH, &old);
	}
	printf("\n");
#endif /* __CK_DOING_TESTS */

	dis_printf(
		L_DEBUG,
		"New memory allocation at %p (%#" F_SIZE_T " byte allocated)\n",
		(void*) *lineptr,
		n
	);

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
		dis_printf(L_ERROR, "Invalid parameter given to user_key().\n");
		return FALSE;
	}


	uint16_t* utf16_password = NULL;
	size_t    utf16_length   = 0;
	uint8_t   user_hash[32]  = {0,};

	/*
	 * We first get the SHA256(SHA256(to_UTF16(user_password)))
	 */
	utf16_length   = (strlen((char*) user_password)+1) * sizeof(uint16_t);
	utf16_password = dis_malloc(utf16_length);

	if(!asciitoutf16(user_password, utf16_password))
	{
		dis_printf(
			L_ERROR,
			"Can't convert user password to UTF-16, aborting.\n"
		);
		memclean(utf16_password, utf16_length);
		return FALSE;
	}

	dis_printf(L_DEBUG, "UTF-16 user password:\n");
	hexdump(L_DEBUG, (uint8_t*) utf16_password, utf16_length);

	/* We're not taking the '\0\0' end of the UTF-16 string */
	SHA256((unsigned char *) utf16_password, utf16_length-2, user_hash);
	SHA256((unsigned char *) user_hash,      32,             user_hash);

	/*
	 * We then pass it to the key stretching manipulation
	 */
	if(!stretch_user_key(user_hash, (uint8_t *) salt, result_key))
	{
		dis_printf(L_ERROR, "Can't stretch the user password, aborting.\n");
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

	*up = NULL;

	ssize_t nb_read;

	const char* env_pass = getenv("DISLOCKER_PASSWORD");

	if(env_pass)
	{
		#ifndef __CK_DOING_TESTS
			printf("Reading user password from the environment\n");
			fflush(NULL);
		#endif /* __CK_DOING_TESTS */
		nb_read = (ssize_t)strlen(env_pass);
		uint8_t* tmp = malloc((size_t)nb_read+2);
		memcpy(tmp, env_pass, (size_t)nb_read);
		*(tmp + nb_read) = '\n';
		*(tmp + nb_read + 1) = '\0';
		*up = tmp;
	}else{
		/* There's no need for a prompt if we're doing tests */
		#ifndef __CK_DOING_TESTS
			printf("Enter the user password: ");
			fflush(NULL);
		#endif /* __CK_DOING_TESTS */

		nb_read = my_getpass((char**) up, stdin);
	}

	if(nb_read <= 0)
	{
		if(*up)
			dis_free(*up);
		*up = NULL;
		dis_printf(L_ERROR, "Can't get a user password using getline()\n");
		return FALSE;
	}

	// getline() gets the '\n' character, so we need to remove it
	chomp((char*) *up);

	return TRUE;
}
