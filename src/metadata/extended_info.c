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

#include "dislocker/metadata/extended_info.h"


/**
 * Print the extended info structure
 *
 * @param level The level to print the message
 * @param xinfo The extended_info_t structure to print
 */
void print_extended_info(DIS_LOGS level, extended_info_t* xinfo)
{
	dis_printf(level, "Unknown:\n");
	hexdump(level, (uint8_t*)&xinfo->unknown1, 2);
	dis_printf(level, "Size: 0x%1$04x (%1$hu)\n", xinfo->size);
	dis_printf(level, "Unknown:\n");
	hexdump(level, (uint8_t*)&xinfo->unknown2, 4);
	dis_printf(level, "Flags: 0x%1$" PRIx64 " (%1$" PRIu64 ")\n", xinfo->flags);
	dis_printf(level, "Convert Log offset: 0x%016"  PRIx64 "\n", xinfo->convertlog_addr);
	dis_printf(level, "Convert Log size:   0x%1$08x (%1$u)\n",    xinfo->convertlog_size);
	dis_printf(level, "Sector size (1): 0x%1$x (%1$d)\n", xinfo->sector_size1);
	dis_printf(level, "Sector size (2): 0x%1$x (%1$d)\n", xinfo->sector_size2);
}

#ifdef _HAVE_RUBY

VALUE rb_datum_virtualization_extinfo_to_s(extended_info_t* xinfo)
{
	VALUE rb_str = rb_str_new("", 0);

	rb_str_catf(rb_str, "Unknown: 0x%04hx\n", xinfo->unknown1);
	rb_str_catf(rb_str, "Size: 0x%1$04x (%1$hu)\n", xinfo->size);
	rb_str_catf(rb_str, "Unknown: 0x%08x\n", xinfo->unknown2);
	rb_str_catf(rb_str, "Flags: 0x%1$"  PRIx64 " (%1$" PRIu64 ")\n", xinfo->flags);
	rb_str_catf(rb_str, "Convert Log offset: 0x%016"  PRIx64 "\n", xinfo->convertlog_addr);
	rb_str_catf(rb_str, "Convert Log size:   0x%1$08x (%1$u)\n",    xinfo->convertlog_size);
	rb_str_catf(rb_str, "Sector size (1): 0x%1$x (%1$d)\n", xinfo->sector_size1);
	rb_str_catf(rb_str, "Sector size (2): 0x%1$x (%1$d)\n", xinfo->sector_size2);

	return rb_str;
}

#endif /* _HAVE_RUBY */
