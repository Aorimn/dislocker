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


#include <getopt.h>

#include "common.h"
#include "config.h"



/**
 * Print program's usage
 */
void usage()
{
	fprintf(stderr,
PROGNAME " by " AUTHOR ", v"VERSION " (compiled for " __OS "/" __ARCH ")\n"
"\n"
"Usage: " PROGNAME " [-hqrv] [-l LOG_FILE] [-o OFFSET] [-V VOLUME DECRYPTMETHOD -F[N]] [-- ARGS...]\n"
"    with DECRYPTMETHOD = -p[RECOVERY_PASSWORD]|-f BEK_FILE|-u[USER_PASSWORD]|-k FVEK_FILE|-c\n"
"\n"
"Options:\n"
"    -c, --clearkey        decrypt volume using a clear key (default)\n"
"    -f, --bekfile BEKFILE\n"
"                          decrypt volume using the bek file (on USB key)\n"
"    -F, --force-block N   force use of metadata block number N (1, 2 or 3)\n"
"    -h, --help            print this help and exit\n"
"    -k, --fvek FVEK_FILE  decrypt volume using the FVEK directly\n"
"    -l, --logfile LOG_FILE\n"
"                          put messages into this file (stdout by default)\n"
"    -o, --offset OFFSET   BitLocker partition offset (default is 0)\n"
"    -p, --recovery-password[RECOVERY_PASSWORD]\n"
"                          decrypt volume using the recovery password method\n"
"    -q, --quiet           do NOT display anything\n"
"    -r, --readonly        do not allow to write on the BitLocker volume\n"
"    -u, --user-password   decrypt volume using the user password method\n"
"    -v, --verbosity       increase verbosity (CRITICAL errors are displayed by default)\n"
"    -V, --volume VOLUME   volume to get metadata and keys from\n"
"\n"
"    --                    end of program options, beginning of FUSE's ones\n"
"\n"
"  ARGS are any arguments you want to pass to FUSE. You need to pass at least\n"
"the mount-point.\n"
"\n"
	);
}


/**
 * Hide a commandline option, replacing the actual optarg by 'X's.
 * 
 * @param opt The option to hide
 */
static void hide_opt(char* opt)
{
	size_t len = strlen(opt);
	
	while(len)
	{
		opt[--len] = 'X';
	}
}


/**
 * Parse arguments strings
 * 
 * @param cfg The config pointer to dis_config_t structure
 * @param argc Number of arguments given to the program
 * @param argv Arguments given to the program
 * @return Return the number of arguments which are still waiting to be studied
 */
int parse_args(dis_config_t* cfg, int argc, char** argv)
{
	/** See man getopt_long(3) */
	extern int optind;
	int optchar = 0;
	
	enum {
		NO_OPT,   /* No option for this argument */
		NEED_OPT, /* Need an option for this one */
		MAY_OPT   /* User may provide an option  */ 
	};
	
	/* Options which could be passed as argument */
	const char          short_opts[] = "cf:F::hk:l:o:p::qru::vV:";
	const struct option long_opts[] = {
		{"clearkey",          NO_OPT,   NULL, 'c'},
		{"bekfile",           NEED_OPT, NULL, 'f'},
		{"force-block",       MAY_OPT,  NULL, 'F'},
		{"help",              NO_OPT,   NULL, 'h'},
		{"logfile",           NEED_OPT, NULL, 'l'},
		{"fvek",              NEED_OPT, NULL, 'k'},
		{"offset",            NEED_OPT, NULL, 'o'},
		{"recovery-password", MAY_OPT,  NULL, 'p'},
		{"quiet",             NO_OPT,   NULL, 'q'},
		{"readonly",          NO_OPT,   NULL, 'r'},
		{"user-password",     MAY_OPT,  NULL, 'u'},
		{"verbosity",         NO_OPT,   NULL, 'v'},
		{"volume",            NEED_OPT, NULL, 'V'},
		{0, 0, 0, 0}
	};
	
	
	/* Some default settings */
	cfg->verbosity       = L_CRITICAL;
	
	while((optchar=getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1)
	{
		switch(optchar)
		{
			case 'c':
				cfg->decryption_mean |= USE_CLEAR_KEY;
				break;
			case 'f':
				if(cfg->bek_file != NULL)
					free(cfg->bek_file);
				cfg->bek_file = (char *) strdup(optarg);
				cfg->decryption_mean |= USE_BEKFILE;
				break;
			case 'F':
				if(optarg)
					cfg->force_block = (unsigned char)
					                          (strtol(optarg, NULL, 10) & 0xff);
				else
					cfg->force_block = 1;
				break;
			case 'h':
				usage();
				free_args(cfg);
				exit(EXIT_SUCCESS);
			case 'k':
				if(cfg->fvek_file != NULL)
					free(cfg->fvek_file);
				cfg->fvek_file = (char *) strdup(optarg);
				cfg->decryption_mean |= USE_FVEKFILE;
				break;
			case 'l':
				if(cfg->log_file != NULL)
					free(cfg->log_file);
				cfg->log_file = (char *) strdup(optarg);
				break;
			case 'o':
				cfg->offset = (off_t) strtoll(optarg, NULL, 10);
				break;
			case 'p':
				if(optarg)
				{
					if(cfg->recovery_password != NULL)
						free(cfg->recovery_password);
					cfg->recovery_password = (uint8_t *) strdup(optarg);
					
					hide_opt(optarg);
				}
				cfg->decryption_mean |= USE_RECOVERY_PASSWORD;
				break;
			case 'q':
				cfg->verbosity = L_QUIET;
				break;
			case 'r':
				cfg->is_ro |= READ_ONLY;
				break;
			case 'u':
				if(optarg)
				{
					if(cfg->user_password != NULL)
						free(cfg->user_password);
					cfg->user_password = (uint8_t *) strdup(optarg);
					
					hide_opt(optarg);
				}
				cfg->decryption_mean |= USE_USER_PASSWORD;
				break;
			case 'v':
				if(cfg->verbosity != L_QUIET)
					cfg->verbosity++;
				break;
			case 'V':
				if(cfg->volume_path != NULL)
					free(cfg->volume_path);
				cfg->volume_path = strdup(optarg);
				break;
			case '?':
			default:
				usage();
				free_args(cfg);
				exit(EXIT_FAILURE);
		}
	}
	
	
	/* Check verbosity */
	if(cfg->verbosity > L_DEBUG)
		cfg->verbosity = L_DEBUG;
	
	/* Check decryption method */
	if(!cfg->decryption_mean)
		cfg->decryption_mean |= USE_CLEAR_KEY;
	
	/* Check if a block is forced */
	if(cfg->force_block != 1 &&
	   cfg->force_block != 2 &&
	   cfg->force_block != 3)
		cfg->force_block = 0;
	
	
	return optind;
}


/**
 * Free dis_config_t members
 * 
 * @param cfg Dislocker's config
 */
void free_args(dis_config_t* cfg)
{
	if(cfg->recovery_password)
		memclean(cfg->recovery_password,
		         strlen((char*)cfg->recovery_password) + sizeof(char));
	
	if(cfg->user_password)
		memclean(cfg->user_password,
		         strlen((char*)cfg->user_password) + sizeof(char));
	
	if(cfg->bek_file)
		memclean(cfg->bek_file, strlen(cfg->bek_file) + sizeof(char));
	
	if(cfg->fvek_file)
		memclean(cfg->fvek_file, strlen(cfg->fvek_file) + sizeof(char));
	
	if(cfg->volume_path)
		xfree(cfg->volume_path);
	
	if(cfg->log_file)
		xfree(cfg->log_file);
}


/**
 * Print read configuration
 */
void print_args(dis_config_t* cfg)
{
	xprintf(L_INFO, "--- Config...\n");
	xprintf(L_INFO, "   Verbosity: %d\n", cfg->verbosity);
	xprintf(L_INFO, "   Trying to decrypt '%s'\n", cfg->volume_path);
	
	switch(cfg->decryption_mean)
	{
		case USE_CLEAR_KEY:
			xprintf(L_INFO,"   \tusing a clear key on the volume.\n");
			break;
		case USE_RECOVERY_PASSWORD:
			xprintf(L_INFO,"   \tusing the following recovery password: '%s'\n",
					cfg->recovery_password);
			break;
		case USE_BEKFILE:
			xprintf(L_INFO,"   \tusing the bek file at '%s'\n", cfg->bek_file);
			break;
		case USE_FVEKFILE:
			xprintf(L_INFO,"   \tusing the FVEK file at '%s'\n", cfg->fvek_file);
			break;
		default:
			break;
	}
	
	if(cfg->force_block)
		xprintf(L_INFO, "   Forced to be using metadata block n°%d\n",
				cfg->force_block);
	else
		xprintf(L_INFO, "   Using the first valid metadata block\n");
	
	if(cfg->is_ro & READ_ONLY)
		xprintf(L_INFO, "   Not allowing any write on the BitLocker volume "
		                "(read only mode)\n");
	
	xprintf(L_INFO, "... End config ---\n");
}

