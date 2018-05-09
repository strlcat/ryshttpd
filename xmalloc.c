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
 * This is a wrapper around host malloc to support telling the sizes
 * of allocated items easily, and it also verifies that object was not overflowed.
 * It ensures at least proper aligning on platforms where size_t is greater than 2.
 * This code must be portable.
 */

#include "httpd.h"

#define ALIGN_SIZES 4
#define PROPER_ALIGN (sizeof(size_t)*ALIGN_SIZES)
#define MGCNUMBER1 0x33ee88aa
#define MGCNUMBER2 0x0d116e93

/* An adopted Jenkins one-at-a-time hash */
#define UIHOP(x, s) do {		\
		hash += (x >> s) & 0xff;\
		hash += hash << 10;	\
		hash ^= hash >> 6;	\
	} while (0)
static size_t uinthash(size_t x)
{
	size_t hash = 0;

	UIHOP(x, 0);
	UIHOP(x, 8);
	UIHOP(x, 16);
	UIHOP(x, 24);

	hash += hash << 3;
	hash ^= hash >> 11;
	hash += hash << 15;

	return hash;
}
#undef UIHOP

static rh_yesno checkptr(const void *p)
{
	size_t *sp;
	size_t sz, x, y;
	char *s;

	if (!p) return NO;

	sp = (size_t *)p-ALIGN_SIZES;
	sz = *sp;
	if (*(sp+1) != (size_t)MGCNUMBER1) return NO;
	if (*(sp+2) != (size_t)MGCNUMBER2) return NO;
	x = uinthash(sz);
	if (x != *(sp+ALIGN_SIZES-1)) return NO;

	s = (char *)sp;
	s += PROPER_ALIGN+sz;
	y = uinthash(x);
	if (memcmp(&y, s, sizeof(size_t)) != 0) return NO;

	return YES;
}

void *rh_malloc(size_t n)
{
	size_t *r;
	size_t x, y;
	char *s;

	if (n == 0) n++;
_try:	r = malloc(PROPER_ALIGN+n+sizeof(size_t));
	if (!r) {
		if (rh_oom(YES, OOM_MALLOC) == YES) goto _try;
		else xerror("rh_malloc");
	}
	else rh_oom(NO, OOM_MALLOC);

	rh_memzero(r, PROPER_ALIGN+n+sizeof(size_t));
	*r = n;
	*(r+1) = (size_t)MGCNUMBER1;
	*(r+2) = (size_t)MGCNUMBER2;
	x = uinthash(n);
	y = uinthash(x);
	s = (char *)r;
	s += PROPER_ALIGN+n;
	memcpy(s, &y, sizeof(size_t));
	*(r+ALIGN_SIZES-1) = x;

	return r+ALIGN_SIZES;
}

#ifdef WITH_TLS
void *rh_calloc(size_t x, size_t y)
{
	return rh_malloc(x * y);
}
#endif

void *rh_realloc(void *p, size_t n)
{
	size_t *r, *t;
	size_t sz, x, y;
	char *s;

	if (!p) return rh_malloc(n);
	else if (p && !n) {
		rh_free(p);
		return NULL;
	}

	if (!checkptr(p)) rh_ub(p);

	r = (size_t *)p-ALIGN_SIZES;
	sz = *r;

_try:	t = realloc(r, PROPER_ALIGN+n+sizeof(size_t));
	if (!t) {
		if (rh_oom(YES, OOM_REALLOC) == YES) goto _try;
		else xerror("rh_realloc");
	}
	else {
		r = t;
		rh_oom(NO, OOM_REALLOC);
	}
	if (sz < n) {
		s = (char *)r;
		s += PROPER_ALIGN+sz;
		rh_memzero(s, n-sz);
	}

	*r = n;
	*(r+1) = (size_t)MGCNUMBER1;
	*(r+2) = (size_t)MGCNUMBER2;
	x = uinthash(n);
	y = uinthash(x);
	s = (char *)r;
	s += PROPER_ALIGN+n;
	memcpy(s, &y, sizeof(size_t));
	*(r+ALIGN_SIZES-1) = x;

	return r+ALIGN_SIZES;
}

void rh_free(void *p)
{
	size_t *r = (size_t *)p-ALIGN_SIZES;

	if (!p) return;
	if (!checkptr(p)) rh_ub(p);
	rh_memzero(p, *r);
	free(r);
}

size_t rh_szalloc(const void *p)
{
	size_t *r = (size_t *)p-ALIGN_SIZES;

	if (!p) return 0;
	if (!checkptr(p)) rh_ub(p);
	return *r;
}
