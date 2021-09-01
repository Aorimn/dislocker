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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <termios.h>
#include <unistd.h>


#include <string.h>
#include <time.h>

#include "dislocker/xstd/xstdio.h"
#include "dislocker/xstd/xstdlib.h"



/* Files descriptors to know where to put logs */
static FILE* fds[DIS_LOGS_NB] = {0,};


/* Keep track of the verbosity level */
static int verbosity = L_QUIET;


/* Levels transcription into strings */
static char* msg_tab[DIS_LOGS_NB] = {
	"CRITICAL",
	"ERROR",
	"WARNING",
	"INFO",
	"DEBUG"
};


/** Saving STDIN parameters before unbufferisation */
static struct termios ti_save;
static int            tty_fd = -1;



/**
 * Initialize outputs for display messages
 *
 * @param v Application verbosity
 * @param file File where putting logs (stdout if NULL)
 */
void dis_stdio_init(DIS_LOGS v, const char* file)
{
	verbosity = v;

	FILE* log = NULL;
	if(file)
	{
		log = fopen(file, LOG_MODE);
		if(!log)
		{
			perror("Error opening log file (falling back to stdout)");
			log = stdout;
		}
	}
	else
		log = stdout;


	switch(v)
	{
		default:
			verbosity = L_DEBUG;
			// fall through
		case L_DEBUG:
			fds[L_DEBUG] = log;
			// fall through
		case L_INFO:
			fds[L_INFO] = log;
			// fall through
		case L_WARNING:
			fds[L_WARNING] = log;
			// fall through
		case L_ERROR:
			fds[L_ERROR] = log;
			// fall through
		case L_CRITICAL:
			fds[L_CRITICAL] = log;
			break;
		case L_QUIET:
			if (log != stdout)
				fclose(log);
			break;
	}

	dis_printf(L_DEBUG, "Verbosity level to %s (%d) into '%s'\n",
	        msg_tab[verbosity], verbosity, file == NULL ? "stdout" : file);
}


/**
 * Create and return an unbuffered stdin
 *
 * @return The file descriptor of the unbuffered input tty
 */
int get_input_fd()
{
	if(tty_fd > -1)
		return tty_fd;

	struct termios ti;

	if ((tty_fd = open("/dev/tty", O_RDONLY | O_NONBLOCK)) < 0)
		return -1;

	tcgetattr(tty_fd, &ti);
	ti_save = ti;
	ti.c_lflag    &= (typeof(tcflag_t)) ~(ICANON | ECHO);
	ti.c_cc[VMIN]  = 1;
	ti.c_cc[VTIME] = 0;
	tcsetattr(tty_fd, TCSANOW, &ti);

	return tty_fd;
}


/**
 * Close the unbuffered stdin if opened
 */
void close_input_fd()
{
	if(tty_fd > -1)
	{
		tcsetattr(tty_fd, TCSANOW, &ti_save);
		close(tty_fd);
	}
}


/**
 * Endify in/outputs
 */
void dis_stdio_end()
{
	close_input_fd();

	if(verbosity > L_QUIET)
		fclose(fds[L_CRITICAL]);
}


/**
 * Remove the '\n', '\r' or '\r\n' before the first '\0' if present
 *
 * @param string String where the '\n', '\r' or '\r\n' is removed
 */
void chomp(char* string)
{
	size_t len = strlen(string);
	if(len == 0)
		return;

	if(string[len - 1] == '\n' || string[len - 1] == '\r')
		string[len - 1] = '\0';

	if(len == 1)
		return;

	if(string[len - 2] == '\r')
		string[len - 2] = '\0';
}


/**
 * Do as printf(3) but displaying nothing if verbosity is not high enough
 * Messages are redirected to the log file if specified into xstdio_init()
 *
 * @param level Level of the message to print
 * @param format String to display (cf printf(3))
 * @param ... Cf printf(3)
 * @return The number of characters printed
 */
int dis_printf(DIS_LOGS level, const char* format, ...)
{
	int ret = -1;

	if(verbosity < level || verbosity <= L_QUIET)
		return 0;

	if(level >= DIS_LOGS_NB)
		level = L_DEBUG;


	va_list arg;
	va_start(arg, format);

	ret = dis_vprintf(level, format, arg);

	va_end(arg);

	fflush(fds[level]);

	return ret;
}


/**
 * Do as vprintf(3) but displaying nothing if verbosity is not high enough
 * Messages are redirected to the log file if specified into xstdio_init()
 *
 * @param level Level of the message to print
 * @param format String to display (cf vprintf(3))
 * @param ap Cf vprintf(3)
 */
int dis_vprintf(DIS_LOGS level, const char* format, va_list ap)
{
	if(verbosity < level || verbosity <= L_QUIET)
		return 0;

	if(level >= DIS_LOGS_NB)
		level = L_DEBUG;

	if(!fds[level])
		return 0;


	time_t current_time = time(NULL);
	char* time2string = ctime(&current_time);

	chomp(time2string);

	fprintf(fds[level], "%s [%s] ", time2string, msg_tab[level]);
	return vfprintf(fds[level], format, ap);
}
