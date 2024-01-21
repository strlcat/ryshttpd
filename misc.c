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

rh_yesno is_number(const char *s, int sign)
{
	char *p;
	if (!s || str_empty(s)) return NO;
	if (sign) strtol(s, &p, 10);
	else {
		if (!isdigit(*s)) return NO;
		strtoul(s, &p, 10);
	}
	return str_empty(p) ? YES : NO;
}

int rh_fcntl(int fd, int cmd, int flags, rh_yesno set)
{
	int ofl = fcntl(fd, cmd);
	if (ofl == -1) return -1;
	if (set) ofl |= flags;
	else ofl &= ~flags;
	return fcntl(fd, cmd, ofl);
}

rh_yesno is_writable(const char *path)
{
	int fd = open(path, O_WRONLY);
	if (fd != -1) {
		close(fd);
		return YES;
	}
	return NO;
}

void useconds_to_timeval(unsigned long long useconds, struct timeval *tv)
{
	rh_memzero(tv, sizeof(struct timeval));
	tv->tv_sec = useconds / 1000000;
	tv->tv_usec = useconds - ((useconds / 1000000) * 1000000);
}

void skeinhash(void *hash, size_t hashsz, const void *msg, size_t msgsz)
{
	struct skein ctx;

	skein_init(&ctx, TF_TO_BITS(hashsz));
	skein_update(&ctx, msg, msgsz);
	skein_final(hash, &ctx);
}
