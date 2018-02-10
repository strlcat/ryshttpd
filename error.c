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

static char no_error_str[] = "no error information";

void rh_ub(const void *offender)
{
	xexits("UB: %p was corrupted!", offender);
}

rh_exit_cb rh_atexit;

void rh_exit(int status)
{
	if (rh_atexit) rh_atexit(status);
	exit(status);
}

void set_progname(const char *name)
{
	char *t;

	t = rh_strdup(name);
	if (progname) pfree(progname);
	progname = rh_strdup(basename(t));
	pfree(t);
}

static void do_error(int status, rh_yesno noexit, const char *f, va_list ap)
{
	char *p;
	va_list t;

	rh_nesay("%s: ", progname);
	va_copy(t, ap);
	rh_nvesay(f, t);
	va_end(t);
	if (errno) p = rh_strerror(errno);
	else p = no_error_str;
	rh_esay(": %s", p);

	if (!noexit) rh_exit(status);
}

void xerror(const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	do_error(2, NO, f, ap);
	va_end(ap);
}

void xerror_status(int status, const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	do_error(status, NO, f, ap);
	va_end(ap);
}

void rh_perror(const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	do_error(2, YES, f, ap);
	va_end(ap);
}

static void do_exits(int status, const char *f, va_list ap)
{
	va_list t;

	rh_nesay("%s: ", progname);
	va_copy(t, ap);
	rh_nvesay(f, t);
	va_end(ap);
	rh_esay("\n");

	rh_exit(status);
}

void xexits(const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	do_exits(2, f, ap);
	va_end(ap);
}

void xexits_status(int status, const char *f, ...)
{
	va_list ap;
	va_start(ap, f);
	do_exits(status, f, ap);
	va_end(ap);
}

char *rh_strerror(int err)
{
	char *serr = strerror(err);
	if (!serr) return no_error_str;
	return serr;
}
