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

char *getmyhostname(void)
{
	char *r = rh_malloc(RH_ALLOC_SMALL);

	if (gethostname(r, RH_ALLOC_SMALL-1) == -1) {
		pfree(r);
		return NULL;
	}
	return r;
}

rh_yesno resolve_ip(int af, const void *sockaddr, socklen_t sockaddrlen, char **ipaddr)
{
	int x;
	char *r;

	r = rh_malloc(NI_MAXHOST);
	x = getnameinfo(sockaddr, sockaddrlen,
		r, NI_MAXHOST, NULL, 0,
		NI_NUMERICHOST | NI_NUMERICSERV);
	if (x) goto _failed;
	shrink_dynstr(&r);

	*ipaddr = r;
	return YES;

_failed:
	rh_asprintf(&r, "%s", gai_strerror(x));
	shrink_dynstr(&r);

	*ipaddr = r;
	return NO;
}

#if 0
/* unused */
rh_yesno resolve_hostname(int af, const void *sockaddr, socklen_t sockaddrlen, char **hostname)
{
	int x;
	char *r;

	r = rh_malloc(NI_MAXHOST);
	x = getnameinfo(sockaddr, sockaddrlen,
		r, NI_MAXHOST, NULL, 0,
		NI_NUMERICSERV);
	if (x) goto _failed;
	shrink_dynstr(&r);

	*hostname = r;
	return YES;

_failed:
	rh_asprintf(&r, "%s", gai_strerror(x));
	shrink_dynstr(&r);

	*hostname = r;
	return NO;
}
#endif

rh_yesno resolve_port(int af, const void *sockaddr, socklen_t sockaddrlen, char **port)
{
	int x;
	char *r;

	r = rh_malloc(NI_MAXSERV);
	x = getnameinfo(sockaddr, sockaddrlen,
		NULL, 0, r, NI_MAXSERV,
		NI_NUMERICHOST | NI_NUMERICSERV);
	if (x) goto _failed;
	shrink_dynstr(&r);

	*port = r;
	return YES;

_failed:
	rh_asprintf(&r, "%s", gai_strerror(x));
	shrink_dynstr(&r);

	*port = r;
	return NO;
}
