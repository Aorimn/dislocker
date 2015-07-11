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
#ifndef XSTDIO_H
#define XSTDIO_H


#include <stdio.h>
#include <stdarg.h>


/* Mode in which the log file is opened */
#define LOG_MODE "a"




/** Messages debug level */
typedef enum {
	L_QUIET    = -1,
	L_CRITICAL = 0, /* default level is 0, whatever 0 is */
	L_ERROR,
	L_WARNING,
	L_INFO,
	L_DEBUG
} DIS_LOGS;

/* Do NOT count the L_QUIET level */
#define DIS_LOGS_NB 5





/*
 * Prototypes of functions from xstdio.c
 */
void dis_stdio_init(int verbosity, const char* logfile);
void dis_stdio_end();
int  get_input_fd();
void close_input_fd();

void chomp(char* string);

int dis_printf(DIS_LOGS level, const char* format, ...);
int dis_vprintf(DIS_LOGS level, const char* format, va_list ap);

void dis_perror(char* append);




#endif /* XSTDIO_H */
