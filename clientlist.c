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

struct clinfo;
struct clinfo {
	struct clinfo *next; /* linked list */
	pid_t clpid; /* it's pid */
	int logfd; /* the fd referring to logging device */
	char *ipaddr; /* ip address */
};

static struct clinfo *cli_head;

void add_client(pid_t pid, int logfd, const char *ipaddr)
{
	struct clinfo *t, *c;

	t = rh_malloc(sizeof(struct clinfo));
	t->clpid = pid;
	t->logfd = logfd;
	t->ipaddr = rh_strdup(ipaddr);

	if (!cli_head) cli_head = t;
	else {
		c = cli_head;
		while (c->next) c = c->next;
		c->next = t;
	}
}

static struct clinfo *find_client_pid(pid_t pid)
{
	struct clinfo *c;

	c = cli_head;
	while (c) {
		if (c->clpid == pid) break;
		c = c->next;
	}

	return c;
}

int get_client_logfd(pid_t pid)
{
	struct clinfo *p;

	p = find_client_pid(pid);
	if (p) return p->logfd;
	return -1;
}

#define DELETE_CLIENT(p) do {		\
		pfree(p->ipaddr);	\
		pfree(p);		\
	} while (0)
void delete_client(pid_t pid)
{
	struct clinfo *p, *c, *t;

	p = find_client_pid(pid);
	if (p) {
		if (p == cli_head) { /* @start-> */
			cli_head = p->next;
			DELETE_CLIENT(p);
		}
		else if (!p->next) { /* ->end<! */
			c = cli_head;
			t = NULL;
			while (c && c->next) {
				t = c;
				c = c->next;
			}
			if (t) t->next = NULL;
			if (c == cli_head) cli_head = NULL;
			DELETE_CLIENT(c);
		}
		else { /* ->somewhere-> */
			c = cli_head;
			while (c) {
				if (c->next == p) break;
				c = c->next;
			}
			if (c) {
				t = c->next;
				c->next = t->next;
				DELETE_CLIENT(t);
			}
		}
	}
}
#undef DELETE_CLIENT

size_t count_clients(const char *ipaddr)
{
	struct netaddr net, addr;
	struct clinfo *c;
	rh_yesno do_ipv6 = NO;
	size_t cnt;

	if (rh_client_ipv6_subnet > 0 && rh_client_ipv6_subnet < 128) {
		if (rh_addr_type(ipaddr) != AF_INET6)
			do_ipv6 = NO;
		if (rh_parse_addr(ipaddr, &net) == NO)
			do_ipv6 = NO;
		net.pfx = rh_client_ipv6_subnet;
		do_ipv6 = YES;
	}

	c = cli_head;
	cnt = 0;
	while (c) {
		if (do_ipv6) {
			if (rh_addr_type(c->ipaddr) != AF_INET6) goto _plain;
			if (rh_parse_addr(c->ipaddr, &addr) == NO)
				goto _plain;

			if (rh_match_addr(&net, &addr) == YES) cnt++;
		}
		else {
_plain:			if (!strcmp(c->ipaddr, ipaddr)) cnt++;
		}
		c = c->next;
	}

	return cnt;
}
