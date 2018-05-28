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

int rh_addr_type(const char *addr)
{
	if (strchr(addr, '.') && !strchr(addr, ':')) return AF_INET;
	else if (strchr(addr, ':') && !strchr(addr, '.')) return AF_INET6;
	return 0;
}

rh_yesno rh_parse_addr(const char *addr, struct netaddr *na)
{
	int type;
	char *s;

	rh_memzero(na, sizeof(struct netaddr));

	type = rh_addr_type(addr);
	if (!type) return NO;
	na->type = type;

	if (na->type == AF_INET) na->pmax = 32;
	else if (na->type == AF_INET6) na->pmax = 128;

	rh_strlcpy(na->saddr, addr, INET6_ADDRSTRLEN);

	s = strchr(na->saddr, '/');
	if (s && *(s+1)) {
		*s = 0; s++;
		na->pfx = atoi(s);
		if (type == AF_INET && na->pfx > 32) return NO;
		else if (type == AF_INET6 && na->pfx > 128) return NO;
	}
	else {
		if (type == AF_INET) na->pfx = 32;
		else na->pfx = 128;
	}

	if (inet_pton(type, na->saddr, na->addr) < 1) return NO;

	return YES;
}

rh_yesno rh_match_addr(const struct netaddr *n, const struct netaddr *a)
{
	int x, y;

	if (n->type != a->type) return NO;

	if ((n->pmax - n->pfx) % 8) {
		for (x = 0; x < (n->pfx/8); x++)
			if (n->addr[x] != a->addr[x]) return NO;
		y = x;
		for (x = (n->pmax - n->pfx) % 8; x < 8; x++) {
			if ((n->addr[y] & (1 << x)) != (a->addr[y] & (1 << x))) return NO;
		}
	}
	else {
		for (x = 0; x < (n->pfx/8); x++)
			if (n->addr[x] != a->addr[x]) return NO;
	}

	return YES;
}
