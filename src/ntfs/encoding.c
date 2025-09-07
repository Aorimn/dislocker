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

#include <iconv.h>
#include <locale.h>
#include "dislocker/ntfs/encoding.h"


/**
 * Convert an UTF-16 string into a wchar_t string. wchar_t may be defined as
 * UTF-16 or UTF-32, this function doesn't care.
 * The UTF-32 string is supposed to be, at least, utf16_length*2 long.
 *
 * @param utf16 An UTF-16 string
 * @param utf16_length The UTF-16 string length
 * @param utf32 The wchar_t string resulted from the conversion
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int utf16towchars(uint16_t* utf16, size_t utf16_length, wchar_t* utf32)
{
	if(!utf16 || !utf32)
		return FALSE;

	memset(utf32, 0, utf16_length*2);

	size_t loop = 0;
	size_t nb_iter = utf16_length/2;

	for(loop = 0; loop < nb_iter; ++loop)
		utf32[loop] = utf16[loop];

	return TRUE;
}

/**
 * Convert an ascii null-terminated string into an UTF-16 null-terminated
 * string.
 * The UTF-16 string is supposed to be, at least, (strlen(ascii)+1)*2 long.
 *
 * @param ascii A null-terminated ascii string
 * @param utf16 The UTF-16 string resulted from the conversion
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int asciitoutf16(const uint8_t* ascii, uint16_t* utf16)
{
	if(!ascii || !utf16)
		return FALSE;

	size_t len = strlen((char*)ascii);
	memset(utf16, 0, (len+1)*2);

	size_t loop = 0;
	for(loop = 0; loop < len; loop++)
		utf16[loop] = ascii[loop];

	return TRUE;
}

/**
 * Convert a null-terminated string into an UTF-16 null-terminated
 * string.
 * The UTF-16 string is supposed to be, at least, (strlen(ascii)+1)*2 long.
 *
 * @param inbuffer  A null-terminated string (encoding depends on locale)
 * @param outbuffer The UTF-16 string resulted from the conversion
 * @return TRUE if result can be trusted, FALSE otherwise
 */
int toutf16(const uint8_t* inbuffer, uint8_t* outbuffer)
{
	iconv_t cd;                              /* Conversion descriptor          */
	char* inptr;                             /* Pointer used for input buffer  */
	char* outptr;                            /* Pointer used for output buffer */
	int rc;                                  /* Return code of iconv()         */

	char* incharset      = NULL;
	char* outcharset     = "UTF-16LE";

	if(!inbuffer || !outbuffer)
		return FALSE;

	size_t lenib = strlen((char*)inbuffer);
	size_t lenob = (lenib+1)*2;

	/* Get the character set from environment */
	incharset = getlocalcharset();
	if (!incharset) {
		dis_printf(L_ERROR, "Could not detect locale, aborting.\n");
		return FALSE;
	}
	dis_printf(L_DEBUG, "Current character set is: %s\n", incharset);

	/* Allocate descriptor for character set conversion */
	if ((cd = iconv_open(outcharset, incharset)) == (iconv_t)(-1)) {
		dis_printf(
			L_ERROR,
			"Cannot allocate descriptor for conversion from %s to %s, aborting.\n",
			incharset, outcharset
		);
		free(incharset);
		return FALSE;
	}

	/* Pointers to in and out buffers */
	inptr = (char*)inbuffer;
	outptr = (char*)outbuffer;

	/* Clean the out buffer */
	memset(outbuffer, 0, lenob);

	/* Convert string from incharset to UTF-16LE */
	rc = (int)iconv(cd, &inptr, &lenib, &outptr, &lenob);
	if (rc == -1) {
		dis_printf(
			L_ERROR,
			"Error in converting characters from %s to %s, aborting.\n",
			incharset, outcharset
		);
		free(incharset);
		return FALSE;
	}

	/* Deallocate descriptor for character conversion */
	iconv_close(cd);

	free(incharset);

	return TRUE;
}

/**
 * Get the character set from the environment
 *
 * @return A string with the character set, NULL otherwise
 */
char* getlocalcharset() {
	char*  cl                  = NULL;
	char*  current_locale      = NULL;
	char*  nl                  = NULL;
	char*  new_locale          = NULL;
	char*  local_charset       = NULL;
	int    local_charset_index, i;
	char** character_sets_list = NULL;

	/*
	 * Get program's current locale: it is "C" when it has not been modified before
	 * But we need it in order to set it back after getting the locale from the environment
	 */
	cl = setlocale(LC_ALL, NULL);
	current_locale = (char*) malloc (strlen(cl)+1);
	if (!current_locale) {
		dis_printf(L_ERROR, "Could not allocate memory for current locale.\n");
		return NULL;
	}
	/* A copy, otherwise not possible to set the locale back to original value */
	strcpy(current_locale, cl);
	dis_printf(L_DEBUG, "Program's locale: %s\n", current_locale);

	/* Set the locale from environment */
	setlocale(LC_ALL, "");

	/* Get program's new locale: now the environment's locale */
	nl = setlocale(LC_ALL, NULL);
	new_locale = (char*) malloc (strlen(nl)+1);
	if (!new_locale) {
		dis_printf(L_ERROR, "Could not allocate memory for new locale.\n");
		/* Sets program's original locale */
		setlocale(LC_ALL, current_locale);
		free(current_locale);
		return NULL;
	}
	/* A copy, otherwise not possible to use it */
	strcpy(new_locale, nl);
	dis_printf(L_DEBUG, "Environment's locale: %s\n", new_locale);

	/* Sets program's original locale */
	setlocale(LC_ALL, current_locale);
	free(current_locale);


	/* Gets the list of valid character sets */
	character_sets_list=buildcharactersetslist();


	/* Search for valid character set in environment's locale
	 * A list of valid character sets is provided by command "iconv -l" in the command line
	 * This list is used to find the character set of the environment's locale
	 */
	i = 0;
	local_charset_index = -1;
	/* Loop over all valid character sets */
	while (strcmp(character_sets_list[i], "DISLOCKER-END_OF_LIST") != 0) {
		/* If a valid character set is found */
		if (strstr(new_locale, character_sets_list[i])) {
			/* If no valid character set has been found before */
			if (local_charset_index < 0) {
				/* Set the current character set */
				dis_printf(L_DEBUG, "A possible character set was found: %s\n", character_sets_list[i]);
				local_charset_index = i;
			}
			/* A valid charset have been found before, but was it the correct one? */
			else
				/* Verify if a new valid character set is found */
				if (strlen(character_sets_list[i]) >= strlen(character_sets_list[local_charset_index])) {
					/* Set the current character set */
					dis_printf(L_DEBUG, "A new possible character set was found: %s\n", character_sets_list[i]);
					local_charset_index = i;
				}
		}
		i++;
	}
	/* Not needed anymore */
	free(new_locale);

	/* Check if a valid character set was found */
	if (local_charset_index < 0) {
		dis_printf(L_ERROR, "Could not find any valid character set.\n");
		return NULL;
	}

	/* Copy the valid character set */
	local_charset = (char*) malloc (strlen(character_sets_list[local_charset_index])+1);
	if (!local_charset) {
		dis_printf(L_ERROR, "Could not allocate memory for local character set.\n");
		return NULL;
	}
	/* A copy, otherwise not possible to use it */
	strcpy(local_charset, character_sets_list[local_charset_index]);

	return local_charset;
}

char** buildcharactersetslist(void) {
	/*
	 * List of all character sets supported by iconv
	 */
	static char *character_sets_list[] = {
		"ANSI_X3.4-1968", "ANSI_X3.4-1986", "ASCII", "CP367", "IBM367", "ISO-IR-6", "ISO646-US", "ISO_646.IRV:1991", "US", "US-ASCII", "CSASCII",
		"UTF-8", "UTF8",
		"UTF-8-MAC", "UTF8-MAC",
		"ISO-10646-UCS-2", "UCS-2", "CSUNICODE",
		"UCS-2BE", "UNICODE-1-1", "UNICODEBIG", "CSUNICODE11",
		"UCS-2LE", "UNICODELITTLE",
		"ISO-10646-UCS-4", "UCS-4", "CSUCS4",
		"UCS-4BE",
		"UCS-4LE",
		"UTF-16",
		"UTF-16BE",
		"UTF-16LE",
		"UTF-32",
		"UTF-32BE",
		"UTF-32LE",
		"UNICODE-1-1-UTF-7", "UTF-7", "CSUNICODE11UTF7",
		"UCS-2-INTERNAL",
		"UCS-2-SWAPPED",
		"UCS-4-INTERNAL",
		"UCS-4-SWAPPED",
		"C99",
		"JAVA",
		"CP819", "IBM819", "ISO-8859-1", "ISO-IR-100", "ISO8859-1", "ISO_8859-1", "ISO_8859-1:1987", "L1", "LATIN1", "CSISOLATIN1",
		"ISO-8859-2", "ISO-IR-101", "ISO8859-2", "ISO_8859-2", "ISO_8859-2:1987", "L2", "LATIN2", "CSISOLATIN2",
		"ISO-8859-3", "ISO-IR-109", "ISO8859-3", "ISO_8859-3", "ISO_8859-3:1988", "L3", "LATIN3", "CSISOLATIN3",
		"ISO-8859-4", "ISO-IR-110", "ISO8859-4", "ISO_8859-4", "ISO_8859-4:1988", "L4", "LATIN4", "CSISOLATIN4",
		"CYRILLIC", "ISO-8859-5", "ISO-IR-144", "ISO8859-5", "ISO_8859-5", "ISO_8859-5:1988", "CSISOLATINCYRILLIC",
		"ARABIC", "ASMO-708", "ECMA-114", "ISO-8859-6", "ISO-IR-127", "ISO8859-6", "ISO_8859-6", "ISO_8859-6:1987", "CSISOLATINARABIC",
		"ECMA-118", "ELOT_928", "GREEK", "GREEK8", "ISO-8859-7", "ISO-IR-126", "ISO8859-7", "ISO_8859-7", "ISO_8859-7:1987", "ISO_8859-7:2003", "CSISOLATINGREEK",
		"HEBREW", "ISO-8859-8", "ISO-IR-138", "ISO8859-8", "ISO_8859-8", "ISO_8859-8:1988", "CSISOLATINHEBREW",
		"ISO-8859-9", "ISO-IR-148", "ISO8859-9", "ISO_8859-9", "ISO_8859-9:1989", "L5", "LATIN5", "CSISOLATIN5",
		"ISO-8859-10", "ISO-IR-157", "ISO8859-10", "ISO_8859-10", "ISO_8859-10:1992", "L6", "LATIN6", "CSISOLATIN6",
		"ISO-8859-11", "ISO8859-11", "ISO_8859-11",
		"ISO-8859-13", "ISO-IR-179", "ISO8859-13", "ISO_8859-13", "L7", "LATIN7",
		"ISO-8859-14", "ISO-CELTIC", "ISO-IR-199", "ISO8859-14", "ISO_8859-14", "ISO_8859-14:1998", "L8", "LATIN8",
		"ISO-8859-15", "ISO-IR-203", "ISO8859-15", "ISO_8859-15", "ISO_8859-15:1998", "LATIN-9",
		"ISO-8859-16", "ISO-IR-226", "ISO8859-16", "ISO_8859-16", "ISO_8859-16:2001", "L10", "LATIN10",
		"KOI8-R", "CSKOI8R",
		"KOI8-U",
		"KOI8-RU",
		"CP1250", "MS-EE", "WINDOWS-1250",
		"CP1251", "MS-CYRL", "WINDOWS-1251",
		"CP1252", "MS-ANSI", "WINDOWS-1252",
		"CP1253", "MS-GREEK", "WINDOWS-1253",
		"CP1254", "MS-TURK", "WINDOWS-1254",
		"CP1255", "MS-HEBR", "WINDOWS-1255",
		"CP1256", "MS-ARAB", "WINDOWS-1256",
		"CP1257", "WINBALTRIM", "WINDOWS-1257",
		"CP1258", "WINDOWS-1258",
		"850", "CP850", "IBM850", "CSPC850MULTILINGUAL",
		"862", "CP862", "IBM862", "CSPC862LATINHEBREW",
		"866", "CP866", "IBM866", "CSIBM866",
		"MAC", "MACINTOSH", "MACROMAN", "CSMACINTOSH",
		"MACCENTRALEUROPE",
		"MACICELAND",
		"MACCROATIAN",
		"MACROMANIA",
		"MACCYRILLIC",
		"MACUKRAINE",
		"MACGREEK",
		"MACTURKISH",
		"MACHEBREW",
		"MACARABIC",
		"MACTHAI",
		"HP-ROMAN8", "R8", "ROMAN8", "CSHPROMAN8",
		"NEXTSTEP",
		"ARMSCII-8",
		"GEORGIAN-ACADEMY",
		"GEORGIAN-PS",
		"KOI8-T",
		"CP154", "CYRILLIC-ASIAN", "PT154", "PTCP154", "CSPTCP154",
		"MULELAO-1",
		"CP1133", "IBM-CP1133",
		"ISO-IR-166", "TIS-620", "TIS620", "TIS620-0", "TIS620.2529-1", "TIS620.2533-0", "TIS620.2533-1",
		"CP874", "WINDOWS-874",
		"VISCII", "VISCII1.1-1", "CSVISCII",
		"TCVN", "TCVN-5712", "TCVN5712-1", "TCVN5712-1:1993",
		"ISO-IR-14", "ISO646-JP", "JIS_C6220-1969-RO", "JP", "CSISO14JISC6220RO",
		"JISX0201-1976", "JIS_X0201", "X0201", "CSHALFWIDTHKATAKANA",
		"ISO-IR-87", "JIS0208", "JIS_C6226-1983", "JIS_X0208", "JIS_X0208-1983", "JIS_X0208-1990", "X0208", "CSISO87JISX0208",
		"ISO-IR-159", "JIS_X0212", "JIS_X0212-1990", "JIS_X0212.1990-0", "X0212", "CSISO159JISX02121990",
		"CN", "GB_1988-80", "ISO-IR-57", "ISO646-CN", "CSISO57GB1988",
		"CHINESE", "GB_2312-80", "ISO-IR-58", "CSISO58GB231280",
		"CN-GB-ISOIR165", "ISO-IR-165",
		"ISO-IR-149", "KOREAN", "KSC_5601", "KS_C_5601-1987", "KS_C_5601-1989", "CSKSC56011987",
		"EUC-JP", "EUCJP", "EXTENDED_UNIX_CODE_PACKED_FORMAT_FOR_JAPANESE", "CSEUCPKDFMTJAPANESE",
		"MS_KANJI", "SHIFT-JIS", "SHIFT_JIS", "SJIS", "CSSHIFTJIS",
		"CP932",
		"ISO-2022-JP", "CSISO2022JP",
		"ISO-2022-JP-1",
		"ISO-2022-JP-2", "CSISO2022JP2",
		"CN-GB", "EUC-CN", "EUCCN", "GB2312", "CSGB2312",
		"GBK",
		"CP936", "MS936", "WINDOWS-936",
		"GB18030",
		"ISO-2022-CN", "CSISO2022CN",
		"ISO-2022-CN-EXT",
		"HZ", "HZ-GB-2312",
		"EUC-TW", "EUCTW", "CSEUCTW",
		"BIG-5", "BIG-FIVE", "BIG5", "BIGFIVE", "CN-BIG5", "CSBIG5",
		"CP950",
		"BIG5-HKSCS:1999",
		"BIG5-HKSCS:2001",
		"BIG5-HKSCS", "BIG5-HKSCS:2004", "BIG5HKSCS",
		"EUC-KR", "EUCKR", "CSEUCKR",
		"CP949", "UHC",
		"CP1361", "JOHAB",
		"ISO-2022-KR", "CSISO2022KR",
		"CP856",
		"CP922",
		"CP943",
		"CP1046",
		"CP1124",
		"CP1129",
		"CP1161", "IBM-1161", "IBM1161", "CSIBM1161",
		"CP1162", "IBM-1162", "IBM1162", "CSIBM1162",
		"CP1163", "IBM-1163", "IBM1163", "CSIBM1163",
		"DEC-KANJI",
		"DEC-HANYU",
		"437", "CP437", "IBM437", "CSPC8CODEPAGE437",
		"CP737",
		"CP775", "IBM775", "CSPC775BALTIC",
		"852", "CP852", "IBM852", "CSPCP852",
		"CP853",
		"855", "CP855", "IBM855", "CSIBM855",
		"857", "CP857", "IBM857", "CSIBM857",
		"CP858",
		"860", "CP860", "IBM860", "CSIBM860",
		"861", "CP-IS", "CP861", "IBM861", "CSIBM861",
		"863", "CP863", "IBM863", "CSIBM863",
		"CP864", "IBM864", "CSIBM864",
		"865", "CP865", "IBM865", "CSIBM865",
		"869", "CP-GR", "CP869", "IBM869", "CSIBM869",
		"CP1125",
		"EUC-JISX0213",
		"SHIFT_JISX0213",
		"ISO-2022-JP-3",
		"BIG5-2003",
		"ISO-IR-230", "TDS565",
		"ATARI", "ATARIST",
		"RISCOS-LATIN1",
		"DISLOCKER-END_OF_LIST"
	};

	return character_sets_list;
}
