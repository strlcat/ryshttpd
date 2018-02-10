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

#include "httpd.h"

char *getsdate(time_t t, const char *fmt, rh_yesno gmt)
{
	char *r;
	size_t rn;
	struct tm *tmnow;

	rn = 64;
	r = rh_malloc(rn);

	if (!fmt) fmt = "%c";
	tmnow = (gmt == YES) ? gmtime(&t) : localtime(&t);
	if (!tmnow) {
		rh_asprintf(&r, (gmt == YES) ?
			  "(gmtime error: %s)" : "(localtime error: %s)", rh_strerror(errno));
		return r;
	}
_again:	if (strftime(r, rn, fmt, tmnow) == 0) {
		rn += 64;
		r = rh_realloc(r, rn);
		goto _again;
	}

	shrink_dynstr(&r);
	return r;
}

time_t getdatetime(char **date, const char *fmt)
{
	time_t t = time(NULL);

	if (*date) pfree(*date);
	*date = getsdate(t, fmt, NO);
	return t;
}
