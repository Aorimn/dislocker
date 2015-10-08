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

#ifdef _HAVE_RUBY
#include "dislocker/ruby.h"

VALUE dis_rb_str_vcatf(VALUE str, const char *fmt, va_list ap)
{
	int written = -1;
	size_t len = 1024;

	do {
		char cstr[len];

		written = vsnprintf(cstr, len, fmt, ap);

		if(written < 0)
			rb_raise(rb_eRuntimeError, "vsnprintf error");

		if((size_t) written >= len)
			len *= 2;
		else
		{
			rb_str_cat2(str, cstr);
			break;
		}
	} while(1);

	return str;
}

VALUE dis_rb_str_catf(VALUE str, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	str = rb_str_vcatf(str, format, ap);
	va_end(ap);

	return str;
}

#endif /* _HAVE_RUBY */
