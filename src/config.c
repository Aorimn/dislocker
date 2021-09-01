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


#include <string.h>
#include <getopt.h>

#include "dislocker/common.h"
#include "dislocker/config.priv.h"
#include "dislocker/dislocker.priv.h"





/**
 * Hide a commandline option, replacing the actual optarg by 'X's.
 *
 * @param opt The option to hide
 */
static void hide_opt(char* opt)
{
	if(!opt)
		return;

	size_t len = strlen(opt);

	while(len)
	{
		opt[--len] = 'X';
	}
}


/* These functions are wrappers around the appropriate dis_setopt call */
static void setclearkey(dis_context_t dis_ctx, char* optarg)
{
	(void) optarg;
	int trueval = TRUE;
	dis_setopt(dis_ctx, DIS_OPT_USE_CLEAR_KEY, &trueval);
}
static void setbekfile(dis_context_t dis_ctx, char* optarg)
{
	int trueval = TRUE;
	dis_setopt(dis_ctx, DIS_OPT_USE_BEK_FILE, &trueval);
	dis_setopt(dis_ctx, DIS_OPT_SET_BEK_FILE_PATH, optarg);
}
static void setforceblock(dis_context_t dis_ctx, char* optarg)
{
	off_t force;
	if(optarg)
		force = (unsigned char) strtol(optarg, NULL, 10);
	else
		force = 1;
	dis_setopt(dis_ctx, DIS_OPT_FORCE_BLOCK, &force);
}
static void setfvek(dis_context_t dis_ctx, char* optarg)
{
	int trueval = TRUE;
	dis_setopt(dis_ctx, DIS_OPT_USE_FVEK_FILE, &trueval);
	dis_setopt(dis_ctx, DIS_OPT_SET_FVEK_FILE_PATH, optarg);
}
static void setvmk(dis_context_t dis_ctx, char* optarg)
{
	int trueval = TRUE;
	dis_setopt(dis_ctx, DIS_OPT_USE_VMK_FILE, &trueval);
	dis_setopt(dis_ctx, DIS_OPT_SET_VMK_FILE_PATH, optarg);
}
static void setlogfile(dis_context_t dis_ctx, char* optarg)
{
	dis_setopt(dis_ctx, DIS_OPT_LOG_FILE_PATH, optarg);
}
static void setoffset(dis_context_t dis_ctx, char* optarg)
{
	off_t offset = (off_t) strtoll(optarg, NULL, 10);
	dis_setopt(dis_ctx, DIS_OPT_VOLUME_OFFSET, &offset);
}
static void setrecoverypwd(dis_context_t dis_ctx, char* optarg)
{
	int trueval = TRUE;
	dis_setopt(dis_ctx, DIS_OPT_USE_RECOVERY_PASSWORD, &trueval);
	dis_setopt(dis_ctx, DIS_OPT_SET_RECOVERY_PASSWORD, optarg);
	hide_opt(optarg);
}
static void setquiet(dis_context_t dis_ctx, char* optarg)
{
	(void) optarg;
	DIS_LOGS l = L_QUIET;
	dis_setopt(dis_ctx, DIS_OPT_VERBOSITY, &l);
}
static void setro(dis_context_t dis_ctx, char* optarg)
{
	(void) optarg;
	int trueval = TRUE;
	dis_setopt(dis_ctx, DIS_OPT_READ_ONLY, &trueval);
}
static void setstateok(dis_context_t dis_ctx, char* optarg)
{
	(void) optarg;
	int trueval = TRUE;
	dis_setopt(dis_ctx, DIS_OPT_DONT_CHECK_VOLUME_STATE, &trueval);
}
static void setuserpassword(dis_context_t dis_ctx, char* optarg)
{
	int trueval = TRUE;
	dis_setopt(dis_ctx, DIS_OPT_USE_USER_PASSWORD, &trueval);
	dis_setopt(dis_ctx, DIS_OPT_SET_USER_PASSWORD, optarg);
	hide_opt(optarg);
}
static void setverbosity(dis_context_t dis_ctx, char* optarg)
{
	dis_ctx->cfg.verbosity = (DIS_LOGS)strtol(optarg, NULL, 10);
}


/* Structure used to define dislocker's options */
struct _dis_options {
	struct option opt;
	void (*fn)(dis_context_t dis_ctx, char* optarg);
};

static struct _dis_options dis_opt[] = {
	{ {"clearkey",          no_argument,       NULL, 'c'}, setclearkey },
	{ {"bekfile",           required_argument, NULL, 'f'}, setbekfile },
	{ {"force-block",       optional_argument, NULL, 'F'}, setforceblock },
	{ {"help",              no_argument,       NULL, 'h'}, NULL },
	{ {"fvek",              required_argument, NULL, 'k'}, setfvek },
	{ {"vmk",               required_argument, NULL, 'K'}, setvmk },
	{ {"logfile",           required_argument, NULL, 'l'}, setlogfile },
	{ {"offset",            required_argument, NULL, 'O'}, setoffset },
	{ {"options",           required_argument, NULL, 'o'}, NULL },
	{ {"recovery-password", optional_argument, NULL, 'p'}, setrecoverypwd },
	{ {"quiet",             no_argument,       NULL, 'q'}, setquiet },
	{ {"readonly",          no_argument,       NULL, 'r'}, setro },
	{ {"ro",                no_argument,       NULL, 'r'}, setro },
	{ {"stateok",           no_argument,       NULL, 's'}, setstateok },
	{ {"user-password",     optional_argument, NULL, 'u'}, setuserpassword },
	{ {"verbosity",         no_argument,       NULL, 'v'}, setverbosity },
	{ {"volume",            required_argument, NULL, 'V'}, NULL }
};



/**
 * Print program's usage
 */
void dis_usage()
{
	fprintf(stderr,
PROGNAME " by " AUTHOR ", v" VERSION " (compiled for " __OS "/" __ARCH ")\n"
#ifdef VERSION_DBG
"Compiled version: " VERSION_DBG "\n"
#endif
"\n"
"Usage: " PROGNAME " [-hqrsv] [-l LOG_FILE] [-O OFFSET] [-V VOLUME DECRYPTMETHOD -F[N]] [-- ARGS...]\n"
"    with DECRYPTMETHOD = -p[RECOVERY_PASSWORD]|-f BEK_FILE|-u[USER_PASSWORD]|-k FVEK_FILE|-K VMK_FILE|-c\n"
"\n"
"Options:\n"
"    -c, --clearkey        decrypt volume using a clear key (default)\n"
"    -f, --bekfile BEKFILE\n"
"                          decrypt volume using the bek file (on USB key)\n"
"    -F, --force-block=[N] force use of metadata block number N (1, 2 or 3)\n"
"    -h, --help            print this help and exit\n"
"    -k, --fvek FVEK_FILE  decrypt volume using the FVEK directly\n"
"    -K, --vmk VMK_FILE    decrypt volume using the VMK directly\n"
"    -l, --logfile LOG_FILE\n"
"                          put messages into this file (stdout by default)\n"
"    -O, --offset OFFSET   BitLocker partition offset, in bytes (default is 0)\n"
"    -p, --recovery-password=[RECOVERY_PASSWORD]\n"
"                          decrypt volume using the recovery password method\n"
"    -q, --quiet           do NOT display anything\n"
"    -r, --readonly        do not allow to write on the BitLocker volume\n"
"    -s, --stateok         do not check the volume's state, assume it's ok to mount it\n"
"    -u, --user-password=[USER_PASSWORD]\n"
"                          decrypt volume using the user password method\n"
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
 * Parse the --options parameter's value
 *
 * @param dis_ctx Dislocker's context
 * @param optstr The value passed with the --options parameter
 */
static void parse_options(dis_context_t dis_ctx, char* optstr)
{
	char* tok = NULL;
	size_t nb_options = sizeof(dis_opt)/sizeof(struct _dis_options);
	size_t i;
	size_t opt_len;

	tok = strtok(optstr, ",");
	while(tok != NULL)
	{
		for(i = 0; i < nb_options; i++)
		{
			opt_len = strlen(dis_opt[i].opt.name);
			if(strncmp(dis_opt[i].opt.name, tok, opt_len) == 0)
			{
				if(tok[opt_len] == '=' && tok[opt_len] != '\0')
					dis_opt[i].fn(dis_ctx, &tok[opt_len + 1]);
				else
					dis_opt[i].fn(dis_ctx, NULL);
			}
		}

		tok = strtok(NULL, ",");
	}
}


/**
 * Parse arguments strings
 *
 * @warning If -h/--help is encountered, the help is printed and the program
 * exits (using exit(EXIT_SUCCESS)).
 *
 * @param dis_ctx Dislocker's context
 * @param argc Number of arguments given to the program
 * @param argv Arguments given to the program
 * @return Return the number of arguments which are still waiting to be studied.
 * If -1 is returned, then an error occurred and the configuration isn't set.
 */
int dis_getopts(dis_context_t dis_ctx, int argc, char** argv)
{
	/** See man getopt_long(3) */
	extern int optind;
	int optchar = 0;
	size_t nb_options = sizeof(dis_opt)/sizeof(struct _dis_options);


	/* Options which could be passed as argument */
	const char short_opts[] = "cf:F::hk:K:l:O:o:p::qrsu::vV:";
	struct option* long_opts;

	if(!dis_ctx || !argv)
		return -1;

	dis_config_t* cfg = &dis_ctx->cfg;
	int trueval = TRUE;


	long_opts = malloc(nb_options * sizeof(struct option));
	while(nb_options--)
	{
		long_opts[nb_options].name    = dis_opt[nb_options].opt.name;
		long_opts[nb_options].has_arg = dis_opt[nb_options].opt.has_arg;
		long_opts[nb_options].flag    = dis_opt[nb_options].opt.flag;
		long_opts[nb_options].val     = dis_opt[nb_options].opt.val;
	}


	while((optchar = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1)
	{
		switch(optchar)
		{
			case 'c':
			{
				dis_setopt(dis_ctx, DIS_OPT_USE_CLEAR_KEY, &trueval);
				break;
			}
			case 'f':
			{
				dis_setopt(dis_ctx, DIS_OPT_USE_BEK_FILE, &trueval);
				dis_setopt(dis_ctx, DIS_OPT_SET_BEK_FILE_PATH, optarg);
				break;
			}
			case 'F':
			{
				off_t force;
				if(optarg)
					force = (unsigned char) strtol(optarg, NULL, 10);
				else
					force = 1;
				dis_setopt(dis_ctx, DIS_OPT_FORCE_BLOCK, &force);
				break;
			}
			case 'h':
			{
				dis_usage();
				dis_free_args(dis_ctx);
				exit(EXIT_SUCCESS);
			}
			case 'k':
			{
				dis_setopt(dis_ctx, DIS_OPT_USE_FVEK_FILE, &trueval);
				dis_setopt(dis_ctx, DIS_OPT_SET_FVEK_FILE_PATH, optarg);
				break;
			}
			case 'K':
			{
				dis_setopt(dis_ctx, DIS_OPT_USE_VMK_FILE, &trueval);
				dis_setopt(dis_ctx, DIS_OPT_SET_VMK_FILE_PATH, optarg);
				break;
			}
			case 'l':
			{
				dis_setopt(dis_ctx, DIS_OPT_LOG_FILE_PATH, optarg);
				break;
			}
			case 'O':
			{
				off_t offset = (off_t) strtoll(optarg, NULL, 10);
				dis_setopt(dis_ctx, DIS_OPT_VOLUME_OFFSET, &offset);
				break;
			}
			case 'o':
			{
				parse_options(dis_ctx, optarg);
				break;
			}
			case 'p':
			{
				dis_setopt(dis_ctx, DIS_OPT_USE_RECOVERY_PASSWORD, &trueval);
				dis_setopt(dis_ctx, DIS_OPT_SET_RECOVERY_PASSWORD, optarg);
				hide_opt(optarg);
				break;
			}
			case 'q':
			{
				DIS_LOGS l = L_QUIET;
				dis_setopt(dis_ctx, DIS_OPT_VERBOSITY, &l);
				break;
			}
			case 'r':
			{
				dis_setopt(dis_ctx, DIS_OPT_READ_ONLY, &trueval);
				break;
			}
			case 's':
			{
				dis_setopt(dis_ctx, DIS_OPT_DONT_CHECK_VOLUME_STATE, &trueval);
				break;
			}
			case 'u':
			{
				dis_setopt(dis_ctx, DIS_OPT_USE_USER_PASSWORD, &trueval);
				dis_setopt(dis_ctx, DIS_OPT_SET_USER_PASSWORD, optarg);
				hide_opt(optarg);
				break;
			}
			case 'v':
			{
				if(cfg->verbosity != L_QUIET)
					cfg->verbosity++;
				break;
			}
			case 'V':
			{
				dis_setopt(dis_ctx, DIS_OPT_VOLUME_PATH, optarg);
				break;
			}
			case '?':
			default:
			{
				dis_usage();
				free(long_opts);
				dis_free_args(dis_ctx);
				return -1;
			}
		}
	}


	/* Check verbosity */
	if(cfg->verbosity > L_DEBUG)
		cfg->verbosity = L_DEBUG;
	if(cfg->verbosity < L_CRITICAL)
		cfg->verbosity = L_CRITICAL;

	/* Check decryption method */
	if(!cfg->decryption_mean)
		cfg->decryption_mean |= DIS_USE_CLEAR_KEY;

	/* Check if a block is forced */
	if(cfg->force_block != 1 &&
	   cfg->force_block != 2 &&
	   cfg->force_block != 3)
		cfg->force_block = 0;

	free(long_opts);

	return optind;
}


/**
 * Get dislocker's option
 *
 * @param dis_ctx Dislocker's context
 * @param opt_name The option's name to get
 * @param opt_value The retrieved value of the option. This is stored in
 *opt_value.
 */
int dis_getopt(dis_context_t dis_ctx, dis_opt_e opt_name, void** opt_value)
{
	if (!dis_ctx || !opt_value)
		return FALSE;

	dis_config_t* cfg = &dis_ctx->cfg;

	switch(opt_name)
	{
		case DIS_OPT_VOLUME_PATH:
			*opt_value = cfg->volume_path;
			break;
		case DIS_OPT_USE_CLEAR_KEY:
			if(cfg->decryption_mean & DIS_USE_CLEAR_KEY)
				*opt_value = (void*) TRUE;
			else
				*opt_value = (void*) FALSE;
			break;
		case DIS_OPT_USE_BEK_FILE:
			if(cfg->decryption_mean & DIS_USE_BEKFILE)
				*opt_value = (void*) TRUE;
			else
				*opt_value = (void*) FALSE;
			break;
		case DIS_OPT_SET_BEK_FILE_PATH:
			*opt_value = cfg->bek_file;
			break;
		case DIS_OPT_USE_RECOVERY_PASSWORD:
			if(cfg->decryption_mean & DIS_USE_RECOVERY_PASSWORD)
				*opt_value = (void*) TRUE;
			else
				*opt_value = (void*) FALSE;
			break;
		case DIS_OPT_SET_RECOVERY_PASSWORD:
			*opt_value = cfg->recovery_password;
			break;
		case DIS_OPT_USE_USER_PASSWORD:
			if(cfg->decryption_mean & DIS_USE_USER_PASSWORD)
				*opt_value = (void*) TRUE;
			else
				*opt_value = (void*) FALSE;
			break;
		case DIS_OPT_SET_USER_PASSWORD:
			*opt_value = cfg->user_password;
			break;
		case DIS_OPT_USE_FVEK_FILE:
			if(cfg->decryption_mean & DIS_USE_FVEKFILE)
				*opt_value = (void*) TRUE;
			else
				*opt_value = (void*) FALSE;
			break;
		case DIS_OPT_SET_FVEK_FILE_PATH:
			*opt_value = cfg->fvek_file;
			break;
		case DIS_OPT_USE_VMK_FILE:
			if(cfg->decryption_mean & DIS_USE_VMKFILE)
				*opt_value = (void*) TRUE;
			else
				*opt_value = (void*) FALSE;
			break;
		case DIS_OPT_SET_VMK_FILE_PATH:
			*opt_value = cfg->vmk_file;
			break;
		case DIS_OPT_VERBOSITY:
			*opt_value = (void*) cfg->verbosity;
			break;
		case DIS_OPT_LOG_FILE_PATH:
			*opt_value = cfg->log_file;
			break;
		case DIS_OPT_FORCE_BLOCK:
			*opt_value = (void*) ((long) cfg->force_block);
			break;
		case DIS_OPT_VOLUME_OFFSET:
			*opt_value = (void*) cfg->offset;
			break;
		case DIS_OPT_READ_ONLY:
			if(cfg->flags & DIS_FLAG_READ_ONLY)
				*opt_value = (void*) TRUE;
			else
				*opt_value = (void*) FALSE;
			break;
		case DIS_OPT_DONT_CHECK_VOLUME_STATE:
			if(cfg->flags & DIS_FLAG_DONT_CHECK_VOLUME_STATE)
				*opt_value = (void*) TRUE;
			else
				*opt_value = (void*) FALSE;
			break;
		case DIS_OPT_INITIALIZE_STATE:
			*opt_value = (void*) cfg->init_stop_at;
			break;
	}

	return TRUE;
}


static void set_decryption_mean(dis_config_t* cfg, int set, unsigned value)
{
	if(set == TRUE)
		cfg->decryption_mean |= value;
	else
		cfg->decryption_mean &= (unsigned) ~value;
}


/**
 * Modify dislocker's options one-by-one
 *
 * @param dis_ctx Dislocker's context
 * @param opt_name The option's name to change
 * @param opt_value The new value of the option. Note that this is a pointer. If
 * NULL, the default value -which is not necessarily usable- will be set.
 */
int dis_setopt(dis_context_t dis_ctx, dis_opt_e opt_name, const void* opt_value)
{
	if (!dis_ctx)
		return FALSE;

	dis_config_t* cfg = &dis_ctx->cfg;

	switch(opt_name)
	{
		case DIS_OPT_VOLUME_PATH:
			if(cfg->volume_path != NULL)
				free(cfg->volume_path);
			if(opt_value == NULL)
				cfg->volume_path = NULL;
			else
				cfg->volume_path = strdup((const char*) opt_value);
			break;
		case DIS_OPT_USE_CLEAR_KEY:
			if(opt_value == NULL)
				cfg->decryption_mean &= (unsigned) ~DIS_USE_CLEAR_KEY;
			else
				set_decryption_mean(cfg, *(int*) opt_value, DIS_USE_CLEAR_KEY);
			break;
		case DIS_OPT_USE_BEK_FILE:
			if(opt_value == NULL)
				cfg->decryption_mean &= (unsigned) ~DIS_USE_BEKFILE;
			else
				set_decryption_mean(cfg, *(int*) opt_value, DIS_USE_BEKFILE);
			break;
		case DIS_OPT_SET_BEK_FILE_PATH:
			if(cfg->bek_file != NULL)
				free(cfg->bek_file);
			if(opt_value == NULL)
				cfg->bek_file = NULL;
			else
				cfg->bek_file = strdup((const char*) opt_value);
			break;
		case DIS_OPT_USE_RECOVERY_PASSWORD:
			if(opt_value == NULL)
				cfg->decryption_mean &= (unsigned) ~DIS_USE_RECOVERY_PASSWORD;
			else
				set_decryption_mean(cfg, *(int*) opt_value, DIS_USE_RECOVERY_PASSWORD);
			break;
		case DIS_OPT_SET_RECOVERY_PASSWORD:
			if(cfg->recovery_password != NULL)
				free(cfg->recovery_password);
			if(opt_value == NULL)
				cfg->recovery_password = NULL;
			else
			{
				const char* v = (const char*) opt_value;
				cfg->recovery_password = (uint8_t *) strdup(v);
			}
			break;
		case DIS_OPT_USE_USER_PASSWORD:
			if(opt_value == NULL)
				cfg->decryption_mean &= (unsigned) ~DIS_USE_USER_PASSWORD;
			else
				set_decryption_mean(cfg, *(int*) opt_value, DIS_USE_USER_PASSWORD);
			break;
		case DIS_OPT_SET_USER_PASSWORD:
			if(cfg->user_password != NULL)
				free(cfg->user_password);
			if(opt_value == NULL)
				cfg->user_password = NULL;
			else
			{
				const char* v = (const char*) opt_value;
				cfg->user_password = (uint8_t *) strdup(v);
			}
			break;
		case DIS_OPT_USE_FVEK_FILE:
			if(opt_value == NULL)
				cfg->decryption_mean &= (unsigned) ~DIS_USE_FVEKFILE;
			else
				set_decryption_mean(cfg, *(int*) opt_value, DIS_USE_FVEKFILE);
			break;
		case DIS_OPT_SET_FVEK_FILE_PATH:
			if(cfg->fvek_file != NULL)
				free(cfg->fvek_file);
			if(opt_value == NULL)
				cfg->fvek_file = NULL;
			else
				cfg->fvek_file = strdup((const char*) opt_value);
			break;
		case DIS_OPT_USE_VMK_FILE:
			if(opt_value == NULL)
				cfg->decryption_mean &= (unsigned) ~DIS_USE_VMKFILE;
			else
				set_decryption_mean(cfg, *(int*) opt_value, DIS_USE_VMKFILE);
			break;
		case DIS_OPT_SET_VMK_FILE_PATH:
			if(cfg->vmk_file != NULL)
				free(cfg->vmk_file);
			if(opt_value == NULL)
				cfg->vmk_file = NULL;
			else
				cfg->vmk_file = strdup((const char*) opt_value);
			break;
		case DIS_OPT_VERBOSITY:
			if(opt_value == NULL)
				cfg->verbosity = 0;
			else
			{
				DIS_LOGS l = *(DIS_LOGS*) opt_value;
				if(l >= L_QUIET && l <= L_DEBUG)
					cfg->verbosity = l;
				else
					cfg->verbosity = 0;
			}
			break;
		case DIS_OPT_LOG_FILE_PATH:
			if(cfg->log_file != NULL)
				free(cfg->log_file);
			if(opt_value == NULL)
				cfg->log_file = NULL;
			else
				cfg->log_file = strdup((const char*) opt_value);
			break;
		case DIS_OPT_FORCE_BLOCK:
			if(opt_value == NULL)
				cfg->force_block = 0;
			else
			{
				int uc = *(int*) opt_value;
				if(uc >= 1 && uc <= 3)
					cfg->force_block = (unsigned char) uc;
				else
					cfg->force_block = 0;
			}
			break;
		case DIS_OPT_VOLUME_OFFSET:
			if(opt_value == NULL)
				cfg->offset = 0;
			else
				cfg->offset = *(off_t*) opt_value;
			break;
		case DIS_OPT_READ_ONLY:
			if(opt_value == NULL)
				cfg->flags &= (unsigned) ~DIS_FLAG_READ_ONLY;
			else
			{
				int flag = *(int*) opt_value;
				if(flag == TRUE)
					cfg->flags |= DIS_FLAG_READ_ONLY;
				else
					cfg->flags &= (unsigned) ~DIS_FLAG_READ_ONLY;
			}
			break;
		case DIS_OPT_DONT_CHECK_VOLUME_STATE:
			if(opt_value == NULL)
				cfg->flags &= (unsigned) ~DIS_FLAG_DONT_CHECK_VOLUME_STATE;
			else
			{
				int flag = *(int*) opt_value;
				if(flag == TRUE)
					cfg->flags |= DIS_FLAG_DONT_CHECK_VOLUME_STATE;
				else
					cfg->flags &= (unsigned) ~DIS_FLAG_DONT_CHECK_VOLUME_STATE;
			}
			break;
		case DIS_OPT_INITIALIZE_STATE:
			if(opt_value == NULL)
				cfg->init_stop_at = DIS_STATE_COMPLETE_EVERYTHING;
			else
			{
				dis_state_e state = *(dis_state_e*) opt_value;
				cfg->init_stop_at = state;
			}
			break;
	}

	return TRUE;
}


/**
 * Free dis_config_t members
 *
 * @param cfg Dislocker's config
 */
void dis_free_args(dis_context_t dis_ctx)
{
	if (!dis_ctx)
		return;

	dis_config_t* cfg = &dis_ctx->cfg;

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

	if(cfg->vmk_file)
		memclean(cfg->vmk_file, strlen(cfg->vmk_file) + sizeof(char));

	if(cfg->volume_path)
		dis_free(cfg->volume_path);

	if(cfg->log_file)
		dis_free(cfg->log_file);
}


/**
 * Print read configuration
 */
void dis_print_args(dis_context_t dis_ctx)
{
	if(!dis_ctx)
		return;

	dis_config_t* cfg = &dis_ctx->cfg;

	dis_printf(L_DEBUG, "--- Config...\n");
	dis_printf(L_DEBUG, "   Verbosity: %d\n", cfg->verbosity);
	dis_printf(L_DEBUG, "   Trying to decrypt '%s'\n", cfg->volume_path);

	if(cfg->decryption_mean & DIS_USE_CLEAR_KEY)
	{
		dis_printf(L_DEBUG, "   \tusing a clear key on the volume\n");
	}
	else if(cfg->decryption_mean &  DIS_USE_USER_PASSWORD)
	{
		dis_printf(L_DEBUG, "   \tusing the user's password method\n");
		dis_printf(L_DEBUG, "   \t\t-> '%s'\n", cfg->user_password);
	}
	else if(cfg->decryption_mean & DIS_USE_RECOVERY_PASSWORD)
	{
		dis_printf(L_DEBUG, "   \tusing the recovery password method\n");
		dis_printf(L_DEBUG, "   \t\t-> '%s'\n", cfg->recovery_password);
	}
	else if(cfg->decryption_mean & DIS_USE_BEKFILE)
	{
		dis_printf(L_DEBUG, "   \tusing the bek file at '%s'\n", cfg->bek_file);
	}
	else if(cfg->decryption_mean & DIS_USE_FVEKFILE)
	{
		dis_printf(L_DEBUG, "   \tusing the FVEK file at '%s'\n", cfg->fvek_file);
	}
	else if(cfg->decryption_mean & DIS_USE_VMKFILE)
	{
		dis_printf(L_DEBUG, "   \tusing the VMK file at '%s'\n", cfg->vmk_file);
	}
	else
	{
		dis_printf(L_DEBUG, "   \tnot using any decryption mean\n");
	}

	if(cfg->force_block)
		dis_printf(
			L_DEBUG,
			"   Forced to be using metadata block n°%d\n",
			cfg->force_block
		);
	else
		dis_printf(L_DEBUG, "   Using the first valid metadata block\n");

	if(cfg->flags & DIS_FLAG_READ_ONLY)
		dis_printf(
			L_DEBUG,
			"   Not allowing any write on the BitLocker volume "
			"(read only mode)\n"
		);

	dis_printf(L_DEBUG, "... End config ---\n");
}


/**
 * Getters for the flags
 */
int dis_is_read_only(dis_context_t dis_ctx)
{
	if(!dis_ctx)
		return -1;
	return (dis_ctx->cfg.flags & DIS_FLAG_READ_ONLY);
}

int dis_is_volume_state_checked(dis_context_t dis_ctx)
{
	if(!dis_ctx)
		return -1;
	return !(dis_ctx->cfg.flags & DIS_FLAG_DONT_CHECK_VOLUME_STATE);
}
