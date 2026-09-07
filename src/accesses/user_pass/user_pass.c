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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


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
 * Get the VMK datum using a TPM datum file and a user PIN
 *
 * The TPM datum file contains a raw AES-CCM datum (as obtained from the TPM).
 * The PIN/user password is used together with the salt from the volume metadata
 * to derive an intermediate key that decrypts the TPM datum. The result is then
 * used to decrypt the actual VMK from the volume metadata.
 *
 * @param dis_meta The metadata structure
 * @param cfg The configuration structure (provides tpm_datum_file and user_password)
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_tpm_pin(dis_metadata_t dis_meta,
                          dis_config_t* cfg,
                          void** vmk_datum)
{
	if(!dis_meta || !cfg || !cfg->tpm_datum_file)
		return FALSE;

	uint8_t user_hash[32] = {0,};
	uint8_t salt[16]      = {0,};
	void* vmk_key         = NULL;
	size_t vmk_key_size   = 0;
	int file_fd           = -1;
	off_t file_size;
	ssize_t rs;
	void* tpm_aesccm      = NULL;

	/* If the user password/PIN wasn't provided, ask for it */
	if(!cfg->user_password)
		if(!prompt_up(&cfg->user_password))
		{
			dis_printf(L_ERROR, "Cannot get valid user PIN. Abort.\n");
			return FALSE;
		}

	dis_printf(
		L_DEBUG,
		"Using TPM+PIN method with datum file '%s'.\n",
		cfg->tpm_datum_file
	);

	/* Read the TPM datum file */
	file_fd = dis_open(cfg->tpm_datum_file, O_RDONLY);
	if(file_fd == -1)
	{
		dis_printf(L_ERROR, "Cannot open TPM datum file (%s)\n", cfg->tpm_datum_file);
		return FALSE;
	}

	file_size = dis_lseek(file_fd, 0, SEEK_END);
	if(file_size < (off_t)sizeof(datum_aes_ccm_t) || file_size > 65536)
	{
		dis_printf(
			L_ERROR,
			"Invalid TPM datum file size: %d (expected at least %lu bytes)\n",
			(int)file_size,
			(unsigned long)sizeof(datum_aes_ccm_t)
		);
		dis_close(file_fd);
		return FALSE;
	}

	tpm_aesccm = dis_malloc((size_t)file_size);
	dis_lseek(file_fd, 0, SEEK_SET);
	rs = dis_read(file_fd, tpm_aesccm, (size_t)file_size);
	dis_close(file_fd);

	if(rs != file_size)
	{
		dis_printf(L_ERROR, "Cannot read TPM datum file completely\n");
		dis_free(tpm_aesccm);
		return FALSE;
	}

	dis_printf(L_DEBUG, "TPM datum file read (%d bytes):\n", (int)file_size);
	hexdump(L_DEBUG, tpm_aesccm, (size_t)file_size);

	/*
	 * Iterate over all VMK datums in the metadata, looking for one that
	 * has both a STRETCH_KEY and an AES_CCM nested datum. For each candidate,
	 * try to decrypt the TPM blob with the PIN-derived key, then use the
	 * result to decrypt the actual VMK.
	 */
	void* current_vmk = NULL;

	while(get_next_datum(
			dis_meta,
			DATUMS_ENTRY_VMK,
			DATUMS_VALUE_VMK,
			current_vmk,
			&current_vmk
	))
	{
		/* Look for a STRETCH_KEY nested datum (contains the salt) */
		void* stretch_datum = NULL;
		if(!get_nested_datumvaluetype(
				current_vmk,
				DATUMS_VALUE_STRETCH_KEY,
				&stretch_datum
			) ||
		   !stretch_datum)
		{
			continue;
		}

		memcpy(salt, ((datum_stretch_key_t*) stretch_datum)->salt, 16);

		dis_printf(L_DEBUG, "Found VMK with stretch key, salt:\n");
		hexdump(L_DEBUG, salt, 16);

		/*
		 * Derive the intermediate key from the user PIN and the salt
		 */
		if(!user_key(cfg->user_password, salt, user_hash))
		{
			dis_printf(L_DEBUG, "Cannot stretch user PIN with this salt, trying next VMK.\n");
			continue;
		}

		dis_printf(L_DEBUG, "Derived user hash:\n");
		hexdump(L_DEBUG, user_hash, 32);

		/*
		 * Step 1: Decrypt the TPM datum with the PIN-derived key.
		 * This yields an intermediate VMK key.
		 */
		/*
		 * Initialize to tpm_aesccm so get_vmk's debug print has a
		 * valid datum to display before decryption overwrites it.
		 */
		datum_key_t* intermediate_key = (datum_key_t*) tpm_aesccm;
		if(!get_vmk(
			(datum_aes_ccm_t*) tpm_aesccm,
			user_hash,
			32,
			&intermediate_key
		))
		{
			dis_printf(L_DEBUG, "Cannot decrypt TPM datum with this VMK's salt, trying next.\n");
			continue;
		}

		/* Extract the raw key bytes from the intermediate key datum */
		if(!get_payload_safe(intermediate_key, &vmk_key, &vmk_key_size))
		{
			dis_printf(
				L_DEBUG,
				"Cannot extract payload from intermediate key, trying next.\n"
			);
			dis_free(intermediate_key);
			continue;
		}

		dis_printf(L_DEBUG, "Intermediate VMK key (%lu bytes):\n",
			(unsigned long)vmk_key_size);
		hexdump(L_DEBUG, vmk_key, vmk_key_size);

		/*
		 * Step 2: Get the AES_CCM nested datum from the metadata VMK
		 * and decrypt it with the intermediate key to get the real VMK.
		 */
		void* aesccm_vmk_datum = NULL;
		if(!get_nested_datumvaluetype(
				current_vmk,
				DATUMS_VALUE_AES_CCM,
				&aesccm_vmk_datum
			) ||
		   !aesccm_vmk_datum)
		{
			dis_printf(
				L_DEBUG,
				"No AES_CCM datum in this VMK entry, trying next.\n"
			);
			dis_free(intermediate_key);
			dis_free(vmk_key);
			vmk_key = NULL;
			continue;
		}

		/* Make a copy since get_vmk may modify the pointer */
		size_t aesccm_size = ((datum_aes_ccm_t*)aesccm_vmk_datum)->header.datum_size;
		void* aesccm_copy = dis_malloc(aesccm_size);
		memcpy(aesccm_copy, aesccm_vmk_datum, aesccm_size);

		dis_printf(L_DEBUG, "AES_CCM VMK datum (%lu bytes):\n",
			(unsigned long)aesccm_size);
		hexdump(L_DEBUG, aesccm_copy, aesccm_size);

		datum_key_t* final_vmk = (datum_key_t*) aesccm_copy;
		if(!get_vmk(
			(datum_aes_ccm_t*) aesccm_copy,
			vmk_key,
			(vmk_key_size > 32) ? 32 : vmk_key_size,
			&final_vmk
		))
		{
			dis_printf(
				L_DEBUG,
				"Cannot decrypt VMK with intermediate key, trying next.\n"
			);
			dis_free(intermediate_key);
			dis_free(vmk_key);
			dis_free(aesccm_copy);
			vmk_key = NULL;
			continue;
		}

		/* Success! */
		dis_printf(L_INFO, "Successfully decrypted VMK using TPM+PIN method.\n");
		*vmk_datum = final_vmk;

		dis_free(intermediate_key);
		dis_free(vmk_key);
		dis_free(aesccm_copy);
		dis_free(tpm_aesccm);
		return TRUE;
	}

	dis_printf(
		L_ERROR,
		"Failed to decrypt VMK using TPM+PIN method. "
		"No matching VMK datum found or wrong PIN.\n"
	);
	dis_free(tpm_aesccm);
	return FALSE;
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


	void*     utf16_password    = NULL;
	size_t    utf8_length       = 0;
	size_t    utf16_length      = 0;
	size_t    utf16_real_length = 0;
	uint8_t   user_hash[32]     = {0,};

	/*
	 * We first get the SHA256(SHA256(to_UTF16(user_password)))
	 */
	utf8_length    = strlen((char*) user_password);
	dis_printf(L_DEBUG, "Length of string password: %d\n", utf8_length);
	/* Expected length of UTF-16 string */
	utf16_length   = (utf8_length+1) * 2;
	dis_printf(L_DEBUG, "Expected length of UTF-16 string password: %d\n", utf16_length);

	utf16_password = (uint8_t*)dis_malloc(utf16_length);
	memset(utf16_password, 0, utf16_length);

	if(!toutf16(user_password, (uint8_t*)utf16_password))
	{
		dis_printf(
			L_ERROR,
			"Can't convert user password to UTF-16, now trying with the original way...\n"
		);

		memset(utf16_password, 0, utf16_length);

		if(!asciitoutf16(user_password, (uint16_t*)utf16_password))
		{
			dis_printf(
				L_ERROR,
				"Can't convert user password to UTF-16, aborting.\n"
			);
			memclean(utf16_password, utf16_length);
			return FALSE;
		}
	}

	/* Final real length of the UTF-16 string (without the '\0\0' ending) */
	utf16_real_length = strlen_utf16(utf16_password, utf16_length);
	dis_printf(L_DEBUG, "Real length of UTF-16 string password: %d\n", utf16_real_length);

	dis_printf(L_DEBUG, "UTF-16 user password:\n");
	hexdump(L_DEBUG, (uint8_t*) utf16_password, utf16_real_length);

	/* We're not taking the '\0\0' end of the UTF-16 string */
	SHA256((unsigned char *) utf16_password, utf16_real_length, user_hash);
	SHA256((unsigned char *) user_hash,      32,                user_hash);

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
