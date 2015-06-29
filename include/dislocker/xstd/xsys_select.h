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
#ifndef XSYS_SELECT_h
#define XSYS_SELECT_h

/* According to POSIX.1-2001 */
#include <sys/select.h>
/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>


/*
 * Cf commit ceb9e56b3d1f8c1922e0526c2e841373843460e2 in the glibc tree.
 *
 * Ubuntu 12.04 LTS uses glibc 2.13.
 */
#if defined(__GLIBC__)

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 16
# define DIS_FD_SET(fd, set) FD_SET((unsigned) (fd), (set))
#else
# define DIS_FD_SET(fd, set) FD_SET((fd), (set))
#endif

#else

# define DIS_FD_SET(fd, set) FD_SET((fd), (set))

#endif /* defined(__GLIBC__) */


#endif /* XSYS_SELECT_h */
