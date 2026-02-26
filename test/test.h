/* -*- coding: utf-8 -*- */
/* -*- mode: c -*- */
/*
 * Dislocker -- enables to read/write on BitLocker encrypted partitions under
 * Linux
 * Copyright (C) 2026 Arm Ltd.
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
#ifndef TEST_H_
#define TEST_H_

static int _failures;
static int _tests;
static jmp_buf _jmp;

#define ADD_TEST(name) \
	do { \
		_tests++; \
		int x = setjmp(_jmp); \
		if (!x) \
			name(); \
	} while(0)


static void _CHECK_BUFFERS(const void *a, const void *b, size_t size_a, size_t size_b,
		const char *file_name, const char *func_name, int lineno)
{
	if(size_a != size_b)
	{
		fprintf(stderr, "%s:%s:%d: Buffer size mismatch: %zu != %zu\n",
			file_name, func_name, lineno, size_a, size_b);
		_failures++;
		longjmp(_jmp, 1);
	}
	if (memcmp(a, b, size_a))
	{
		fprintf(stderr, "%s:%s:%d: Buffers do not match\n",
				file_name, func_name, lineno);
		_failures++;
		longjmp(_jmp, 1);
	}
}

#define CHECK_BUFFERS(a, b, a_size, b_size) \
	_CHECK_BUFFERS(a, b, a_size, b_size, __FILE__, __func__, __LINE__)

#define CHECK_STATIC_BUFFERS(a, b) \
		CHECK_BUFFERS(a, b, sizeof(a), sizeof(b))

#define NEW_ARRAY_FROM(t, n, from) \
	t n[sizeof(from)]; \
	memcpy(n, from, sizeof(n));

#endif /* TEST_H_ */
