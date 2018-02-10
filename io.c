/*
 * ryshttpd -- small, plain, fast embedded http server.
 *
 * ryshttpd is copyrighted:
 * Copyright (C) 2018 Andrey Rys. All rights reserved.
 *
 * ryshttpd is licensed to you under the terms of std. MIT/X11 license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/*
 * A comprehensive yet still small byte I/O suite.
 * Portable, easy and pretty simple.
 */

#include "httpd.h"

rh_fsize rh_fdsize(int fd)
{
	off_t l, cur;

	cur = lseek(fd, 0L, SEEK_CUR);
	l = lseek(fd, 0L, SEEK_SET);
	if (l == -1) return NOFSIZE;
	l = lseek(fd, 0L, SEEK_END);
	if (l == -1) return NOFSIZE;
	lseek(fd, cur, SEEK_SET);

	return (rh_fsize)l;
}

size_t io_read_data(int fd, void *data, size_t szdata, rh_yesno noretry, size_t *rdd)
{
	size_t lr, li, ld;
	char *pblk;

	pblk = data;
	lr = szdata;
	ld = 0;
_ragain:
	li = (size_t)read(fd, pblk, lr);
	if (li == 0) {
		if (rdd) *rdd = ld;
		return ld;
	}
	if (li == NOSIZE) return NOSIZE;
	ld += li;
	if (rdd) *rdd = ld;
	if (noretry == NO && li && li < lr) {
		pblk += li;
		lr -= li;
		goto _ragain;
	}

	if (rdd) *rdd = ld;
	return ld;
}

size_t io_write_data(int fd, const void *data, size_t szdata, rh_yesno noretry, size_t *wrd)
{
	size_t lr, li, ld;
	const char *pblk;

	pblk = data;
	lr = szdata;
	ld = 0;
_wagain:
	li = (size_t)write(fd, pblk, lr);
	if (li == NOSIZE) return NOSIZE;
	ld += li;
	if (wrd) *wrd = ld;
	if (noretry == NO && li && li < lr) {
		pblk += li;
		lr -= li;
		goto _wagain;
	}

	if (wrd) *wrd = ld;
	return ld;
}
