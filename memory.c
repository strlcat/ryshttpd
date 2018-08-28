/*
 * ryshttpd -- simple filesharing http server.
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

#include "httpd.h"

rh_yesno memtest(void *p, size_t l, int c)
{
	char t[64];
	size_t xl = l;

	rh_memzero(t, sizeof(t));

	if (xl >= sizeof(t)) {
		do {
			if (memcmp(p+(l-xl), t, sizeof(t)) != 0) return NO;
		} while ((xl -= sizeof(t)) >= sizeof(t));
	}

	if (xl) {
		if (memcmp(p+(l-xl), t, xl) != 0) return NO;
	}

	return YES;
}

void rh_memzero(void *p, size_t l)
{
	memset(p, 0, l);
}

void *rh_memdup(const void *p, size_t sz)
{
	void *r = rh_malloc(sz);
	memcpy(r, p, sz);
	return r;
}

char *rh_strndup(const char *s, size_t max)
{
	size_t n = strnlen(s, max ? max : RH_XSALLOC_MAX);
	char *r = rh_malloc(n+1);
	memcpy(r, s, n);
	return r;
}

char *rh_strdup(const char *s)
{
	return rh_strndup(s, 0);
}

void *append_data(void *block, const void *data, size_t szdata)
{
	void *r = block;
	size_t sz;

	if (!data || szdata == 0) return r;

	sz = rh_szalloc(r);
	r = rh_realloc(r, sz + szdata);
	memcpy(r+sz, data, szdata);

	return r;
}
