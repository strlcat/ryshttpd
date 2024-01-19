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

rh_fsize rh_str_fsize(const char *s, char **stoi)
{
	if (stoi) *stoi = NULL;
	return (rh_fsize)strtoull(s, stoi, 10);
}

size_t rh_str_size(const char *s, char **stoi)
{
	if (stoi) *stoi = NULL;
	return (size_t)strtoull(s, stoi, 10);
}

long rh_str_long(const char *s, char **stoi)
{
	if (stoi) *stoi = NULL;
	return strtol(s, stoi, 10);
}

int rh_str_int(const char *s, char **stoi)
{
	if (stoi) *stoi = NULL;
	return (int)strtol(s, stoi, 10);
}

unsigned rh_str_uint(const char *s, char **stoi)
{
	if (stoi) *stoi = NULL;
	return (unsigned)strtoul(s, stoi, 10);
}

static const char *size_scale[] = {"", "K", "M", "G", "T", "P"};

char *rh_human_fsize(rh_fsize fsize)
{
	double w;
	int scale;
	const char *fmt = "%.2f%s";
	char *r = NULL;

	if (fsize <= 1024) {
		w = fsize;
		scale = 0;
		fmt = "%.0f%s";
	} /* B */
	else if ((fsize > 1024)
		&& (fsize <= 1024ULL * 1024)) {
		w = (double)fsize / 1024;
		scale = 1;
	} /* K */
	else if ((fsize > 1024UL * 1024)
		&& (fsize <= 1024ULL * 1024 * 1024)) {
		w = (double)fsize / (1024UL * 1024);
		scale = 2;
	} /* M */
	else if ((fsize > 1024UL * 1024 * 1024)
		&& (fsize <= 1024ULL * 1024 * 1024 * 1024)) {
		w = (double)fsize / (1024ULL * 1024 * 1024);
		scale = 3;
	} /* G */
	else if ((fsize > 1024ULL * 1024 * 1024 * 1024)
		&& fsize <= 1024ULL * 1024 * 1024 * 1024 * 1024) {
		w = (double)fsize / (1024ULL * 1024 * 1024 * 1024);
		scale = 4;
	} /* T */
	else {
		w = (double)fsize / (1024ULL * 1024 * 1024 * 1024 * 1024);
		scale = 5;
	} /* P */

	rh_asprintf(&r, fmt, w, size_scale[scale]);
	shrink_dynstr(&r);
	return r;
}

rh_fsize rh_str_human_fsize(const char *s, char **stoi)
{
	char pfx[2] = {0, 0};
	char N[32];
	size_t l;
	rh_fsize r;

	if (!s) return 0;

	rh_strlcpy(N, s, sizeof(N));
	l = strnlen(N, sizeof(N));
	pfx[0] = *(N+l-1);
	if (!is_number(pfx, NO)) *(N+l-1) = 0;

	if (stoi) *stoi = NULL;
	if (is_number(pfx, NO) || *pfx == 'B' || *pfx == 'c') r = strtoull(N, stoi, 10);
	else if (*pfx == 'k' || *pfx == 'K') r = strtoull(N, stoi, 10)*1024;
	else if (*pfx == 'm' || *pfx == 'M') r = strtoull(N, stoi, 10)*1024*1024;
	else if (*pfx == 'g' || *pfx == 'G') r = strtoull(N, stoi, 10)*0x40000000ULL;
	else if (*pfx == 'T') r = strtoull(N, stoi, 10)*0x10000000000ULL;
	else if (*pfx == 'P') r = strtoull(N, stoi, 10)*0x4000000000000ULL;
	else r = strtoull(N, stoi, 10);

	return r;
}
