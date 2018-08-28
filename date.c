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

rh_yesno getsdate_r(time_t t, const char *fmt, rh_yesno gmt, char *str, size_t szstr)
{
	struct tm *tmnow;

	if (!fmt) fmt = "%c";
	tmnow = (gmt == YES) ? gmtime(&t) : localtime(&t);
	if (!tmnow) {
		rh_snprintf(str, szstr, (gmt == YES) ?
			  "(gmtime error: %s)" : "(localtime error: %s)", rh_strerror(errno));
		return YES;
	}
	if (strftime(str, szstr, fmt, tmnow) == 0) return NO;

	return YES;
}

char *getsdate(time_t t, const char *fmt, rh_yesno gmt)
{
	char *r;
	size_t rn;

	rn = RH_ALLOC_SMALL;
	r = rh_malloc(rn);
_again:	if (getsdate_r(t, fmt, gmt, r, rn) == NO) {
		rn += RH_ALLOC_SMALL;
		if (rn > RH_XSALLOC_MAX) {
			rh_asprintf(&r, "(getsdate: memory limit exceeded)");
			shrink_dynstr(&r);
			return r;
		}
		r = rh_realloc(r, rn);
		goto _again;
	}

	shrink_dynstr(&r);
	return r;
}

time_t getdatetime_r(char *date, size_t szdate, const char *fmt)
{
	time_t t = time(NULL);

	if (getsdate_r(t, fmt, NO, date, szdate) == NO) return 0;
	return t;
}

time_t getdatetime(char **date, const char *fmt)
{
	time_t t = time(NULL);

	if (*date) pfree(*date);
	*date = getsdate(t, fmt, NO);
	return t;
}
