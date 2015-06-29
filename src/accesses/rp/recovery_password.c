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


#include <errno.h>

#include "dislocker/accesses/rp/recovery_password.h"
#include "dislocker/metadata/vmk.h"
#include "dislocker/xstd/xsys_select.h"



// Specifications of the recovery password
#define NB_RP_BLOCS   8
#define NB_DIGIT_BLOC 6

#define INTERMEDIATE_KEY_LENGTH 32


/**
 * Get the VMK datum using a recovery password
 *
 * @param dis_metadata The metadata structure
 * @param cfg The configuration structure
 * @param vmk_datum The datum_key_t found, containing the unencrypted VMK
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int get_vmk_from_rp(dis_metadata_t dis_meta, dis_config_t* cfg, void** vmk_datum)
{
	// Check parameters
	if(!dis_meta || !cfg)
		return FALSE;

	uint8_t* recovery_key = NULL;
	uint8_t salt[16] = {0,};

	int result = FALSE;

	/* If the recovery password wasn't provide, ask for it */
	if(!cfg->recovery_password)
		if(!prompt_rp(&cfg->recovery_password))
		{
			dis_printf(L_ERROR, "Cannot get valid recovery password. Abort.\n");
			return FALSE;
		}


	dis_printf(L_DEBUG, "Using the recovery password: '%s'.\n",
	                (char *)cfg->recovery_password);


	/*
	 * We need a salt contained in the VMK datum associated to the recovery
	 * password, so go get this salt and the VMK datum first
	 * We use here the range which should be upper (or equal) than 0x800
	 */
	if(!get_vmk_datum_from_range(dis_meta, 0x800, 0xfff, (void**)vmk_datum))
	{
		dis_printf(L_ERROR, "Error, can't find a valid and matching VMK datum. Abort.\n");
		*vmk_datum = NULL;
		return FALSE;
	}


	/*
	 * We have the datum containing other data, so get in there and take the
	 * nested one with type 3 (stretch key)
	 */
	void* stretch_datum = NULL;
	if(!get_nested_datumtype(*vmk_datum, DATUM_STRETCH_KEY, &stretch_datum) || !stretch_datum)
	{
		char* type_str = datumtypestr(DATUM_STRETCH_KEY);
		dis_printf(L_ERROR, "Error looking for the nested datum of type %hd (%s) in the VMK one. "
		                 "Internal failure, abort.\n", DATUM_STRETCH_KEY, type_str);
		dis_free(type_str);
		*vmk_datum = NULL;
		return FALSE;
	}


	/* The salt is in here, don't forget to keep it somewhere! */
	memcpy(salt, ((datum_stretch_key_t*)stretch_datum)->salt, 16);


	/* Get data which can be decrypted with this password */
	void* aesccm_datum = NULL;
	if(!get_nested_datumtype(*vmk_datum, DATUM_AES_CCM, &aesccm_datum) || !aesccm_datum)
	{
		dis_printf(L_ERROR, "Error finding the AES_CCM datum including the VMK. Internal failure, abort.\n");
		*vmk_datum = NULL;
		return FALSE;
	}


	/*
	 * We have all the things we need to compute the intermediate key from
	 * the recovery password, so do it!
	 */
	recovery_key = dis_malloc(32 * sizeof(uint8_t));

	if(!intermediate_key(cfg->recovery_password, salt, recovery_key))
	{
		dis_printf(L_ERROR, "Error computing the recovery password to the recovery key. Abort.\n");
		*vmk_datum = NULL;
		dis_free(recovery_key);
		return FALSE;
	}

	/* We don't need the recovery_password anymore */
	memclean((char*)cfg->recovery_password, strlen((char*)cfg->recovery_password));
	cfg->recovery_password = NULL;

	/* As the computed key length is always the same, use a direct value */
	result = get_vmk((datum_aes_ccm_t*)aesccm_datum, recovery_key, 32, (datum_key_t**)vmk_datum);

	dis_free(recovery_key);

	return result;
}


/**
 * Validating one block of the recovery password
 *
 * @param digits The entire block to validate
 * @param block_nb The block number
 * @param short_password The block divided by 11 and converted into uint16_t
 * @return TRUE if valid, FALSE otherwise
 */
int valid_block(uint8_t* digits, int block_nb, uint16_t* short_password)
{
	// Check the parameters
	if(!digits)
		return FALSE;


	/* Convert chars into int */
	errno = 0;
	long int block = strtol((char *)digits, (char **) NULL, 10);
	if(errno == ERANGE)
	{
		dis_printf(L_ERROR, "Error converting '%s' into a number: errno=ERANGE", digits);
		return FALSE;
	}

	/* 1st check --  Checking if the bloc is divisible by eleven */
	if((block % 11) != 0)
	{
		dis_printf(L_ERROR, "Error handling the recovery password: Bloc n°%d (%d) invalid. "
		"It has to be divisible by 11.\n", block_nb, block);
		return FALSE;
	}

	/* 2nd check -- Checking if the bloc is less than 2**16 * 11 */
	if(block >= 720896)
	{
		dis_printf(L_ERROR,  "Error handling the recovery password: Bloc n°%d (%d) invalid. "
		"It has to be less than 2**16 * 11 (720896).\n", block_nb, block);
		return FALSE;
	}

	/* 3rd check -- Checking if the checksum is correct */
	int8_t check_digit = (int8_t)(digits[0] - digits[1] + digits[2] - digits[3] + digits[4]
									- 48) % 11; /* Convert chars into digits */

	/* Some kind of bug the c modulo has: -2 % 11 yields -2 instead of 9 */
	while(check_digit < 0)
		check_digit = (int8_t)(check_digit + 11);

	if(check_digit != (digits[5] - 48))
	{
		dis_printf(L_ERROR, "Error handling the recovery password: Bloc n°%d (%d) has invalid checksum.\n", block_nb, block);
		return FALSE;
	}

	/*
	 * The bloc has a good look, store a short version of it
	 * We already have checked the size (see 2nd check), a uint16_t can contain
	 * the result
	 */
	if(short_password)
		*short_password = (uint16_t) (block / 11);

	return TRUE;
}


/**
 * Validating (or not) the recovery password.
 * If the password is valid, short_password contains the blocs divided by 11 in
 * uint16_t slot.
 *
 * @param recovery_password The recovery password the user typed (48+7 bytes)
 * @param short_password The recovery password converted in uint16_t (8 uint16_t)
 * @return TRUE if valid, FALSE otherwise
 */
int is_valid_key(const uint8_t *recovery_password, uint16_t *short_password)
{
	// Check the parameters
	if(recovery_password == NULL)
		return FALSE;

	if(short_password == NULL)
		return FALSE;

	/* Begin by checking the length of the password */
	if(strlen((char*)recovery_password) != 48+7)
	{
		dis_printf(L_ERROR, "Error handling the recovery password: Wrong length (has to be %d)\n", 48+7);
		return FALSE;
	}

	const uint8_t *rp = recovery_password;
	uint16_t *sp = short_password;
	uint8_t digits[NB_DIGIT_BLOC + 1];

	int loop = 0;

	for(loop = 0; loop < NB_RP_BLOCS; ++loop)
	{
		memcpy(digits, rp, NB_DIGIT_BLOC);
		digits[NB_DIGIT_BLOC] = 0;

		/* Check block validity */
		if(!valid_block(digits, loop+1, sp))
			return FALSE;

		sp++;
		rp += 7;
	}

	// All of the recovery password seems to be good

	return TRUE;
} // End is_valid_key



/**
 * Calculate the intermediate key from a raw recovery password.
 *
 * @param recovery_password The raw recovery password given by the user (48+7 bytes)
 * @param result_key The intermediate key used to decrypt the associated VMK (32 bytes)
 * @return TRUE if result_key can be trusted, FALSE otherwise
 */
int intermediate_key(const uint8_t *recovery_password,
                     const uint8_t *salt,
                     uint8_t *result_key)
{
	// Check the parameters
	if(recovery_password == NULL)
	{
		dis_printf(L_ERROR, "Error: No recovery password given, aborting calculation of the intermediate key.\n");
		return FALSE;
	}

	if(result_key == NULL)
	{
		dis_printf(L_ERROR, "Error: No space to store the intermediate recovery key, aborting operation.\n");
		return FALSE;
	}


	uint16_t passwd[NB_RP_BLOCS];
	uint8_t *iresult = dis_malloc(INTERMEDIATE_KEY_LENGTH * sizeof(uint8_t));
	uint8_t *iresult_save = iresult;
	int loop = 0;

	memset(passwd,  0, NB_RP_BLOCS * sizeof(uint16_t));
	memset(iresult, 0, INTERMEDIATE_KEY_LENGTH * sizeof(uint8_t));

	/* Check if the recovery_password has a good smile */
	if(!is_valid_key(recovery_password, passwd))
	{
		memclean(iresult, INTERMEDIATE_KEY_LENGTH * sizeof(uint8_t));
		return FALSE;
	}

	// passwd now contains the blocs divided by 11 in a uint16_t tab
	// Convert each one of the blocs in little endian and make it one buffer
	for(loop = 0; loop < NB_RP_BLOCS; ++loop)
	{
		*iresult = (uint8_t)(passwd[loop] & 0x00ff);
		iresult++;
		*iresult = (uint8_t)((passwd[loop] & 0xff00) >> 8);
		iresult++;
	}

	iresult = iresult_save;

	/* Just print it */
	char s[NB_RP_BLOCS*2 * 5 + 1] = {0,};
	for (loop = 0; loop < NB_RP_BLOCS*2; ++loop)
		snprintf(&s[loop*5], 6, "0x%02hhx ", iresult[loop]);

	dis_printf(L_DEBUG, "Distilled password: '%s\b'\n", s);

	stretch_recovery_key(iresult, salt, result_key);

	memclean(iresult, INTERMEDIATE_KEY_LENGTH * sizeof(uint8_t));

	/* We successfuly retrieve the key! */
	return TRUE;
} // End intermediate_key


/**
 * Prompt for the recovery password to be entered
 *
 * @param rp The place where to put the entered recovery password
 * @return TRUE if rp can be trusted, FALSE otherwise
 */
int prompt_rp(uint8_t** rp)
{
	// Check the parameter
	if(!rp)
		return FALSE;


	int in       = get_input_fd();

	char* prompt = "\rEnter the recovery password: ";

	int idx      = 0;
	uint8_t c    = 0;
	int block_nb = 1;
	uint8_t digits[NB_DIGIT_BLOC + 1] = {0,};

	uint8_t* blah = NULL;

	fd_set rfds;
	int    nfds = in + 1;

	if(in < 0)
	{
		fprintf(stderr, "Cannot open tty.\n");
		return FALSE;
	}

	if(FD_SETSIZE < 0)
	{
		fprintf(stderr, "Cannot add fd in the set.\n");
		return FALSE;
	}

	if((unsigned) in >= (unsigned) FD_SETSIZE)
	{
		fprintf(stderr,
		        "Terminal file descriptor (%u) is equal to or larger than "
		        "FD_SETSIZE (%u).\n", (unsigned) in, (unsigned) FD_SETSIZE);
		close_input_fd();
		return FALSE;
	}


	/* 8 = 7 hyphens separating the blocks + 1 '\0' at the end of the string */
	*rp = malloc(NB_RP_BLOCS * NB_DIGIT_BLOC + 8);
	memset(*rp, 0, NB_RP_BLOCS * NB_DIGIT_BLOC + 8);

	blah = *rp;

	printf("%s", prompt);
	fflush(NULL);

	FD_ZERO(&rfds);
	/** @see xstd/xsys_select.h for an explanation of this macro */
	DIS_FD_SET(in, &rfds);

	while(1)
	{
		/* Wait for inputs */
		int selret = select(nfds+1, &rfds, NULL, NULL, NULL);

		/* Look for errors */
		if(selret == -1)
		{
			fprintf(stderr, "Error %d in select: %s\n", errno, strerror(errno));
			break;
		}


		if(read(in, &c, 1) <= 0)
		{
			fprintf(stderr, "Something is available for reading but unable to "
					"read (%d): %s\n", errno, strerror(errno));
			break;
		}

		/* If this is an hyphen, just ignore it */
		if(c == '-')
			continue;

		/* Place the character at the right place or erase the last character */
		if(idx <= NB_DIGIT_BLOC)
		{
			/* If backspace was hit */
			if(c == '\b' || c == '\x7f')
			{
				idx--;

				if(idx < 0 && block_nb > 1)
				{
					blah -= (NB_DIGIT_BLOC + 1);
					snprintf((char*)digits, NB_DIGIT_BLOC, "%s", blah);
					*blah = '\0';
					idx   =  NB_DIGIT_BLOC - 1;
					block_nb--;
				}

				if(idx < 0)
					idx = 0;

				/* Yeah, I agree, this is kinda dirty */
				digits[idx] = ' ';
				printf("%s%s%s", prompt, *rp, digits);

				digits[idx] = '\0';
				idx--;
			}
			else if(c >= '0' && c <= '9')
				digits[idx] = (uint8_t)c;
			else
				continue;
		}

		printf("%s%s%s", prompt, *rp, digits);
		fflush(NULL);
		idx++;

		/* Now if we're at the end of a block, (in)validate it */
		if(idx >= NB_DIGIT_BLOC)
		{
			if(valid_block(digits, block_nb, NULL))
			{
				snprintf((char*)blah, NB_DIGIT_BLOC+1, "%s", digits);
				blah += NB_DIGIT_BLOC;

				if(block_nb >= NB_RP_BLOCS)
				{
					/* Hide the recovery password for sneaky eyes */
					printf("%1$s%2$s-%2$s-%2$s-%2$s-%2$s-%2$s-%2$s-%2$s\n", prompt, "XXXXXX");
					printf("Valid password format, continuing.\n");
					close_input_fd();
					return TRUE;
				}
				else
				{
					putchar('-');
					*blah = '-';
					blah++;
				}

				block_nb++;
			}
			else
			{
				fprintf(stderr, "\nInvalid block.\n");
				printf("%s%s", prompt, *rp);
			}

			fflush(NULL);

			idx = 0;
			memset(digits, 0, NB_DIGIT_BLOC);
		}
	}

	close_input_fd();
	return FALSE;
}


/**
 * Print the result key which can be used to decrypt the associated VMK
 *
 * @param result_key The key after passed to intermediate_key
 */
void print_intermediate_key(uint8_t *result_key)
{
	if(result_key == NULL)
		return;

	int loop = 0;
	char s[32*3 + 1] = {0,};
	for(loop = 0; loop < 32; ++loop)
		snprintf(&s[loop*3], 4, "%02hhx ", result_key[loop]);

	dis_printf(L_INFO, "Intermediate recovery key:\n\t%s\n", s);
}


