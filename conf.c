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

struct config {
	void *cfgdata; /* config file as whole */
	char *d, *t; /* for strtok_r */
};

rh_yesno is_comment(const char *s)
{
	if (str_empty(s)
	|| *s == '#'
	|| *s == '\n'
	|| (*s == '\r' && *(s+1) == '\n')
	|| *s == ';'
	|| (*s == '/' && *(s+1) == '/')) return YES;
	return NO;
}

void *load_config(int fd)
{
	size_t x, sz;
	struct config *r;
	char *s;

	r = rh_malloc(sizeof(struct config));

	sz = (size_t)rh_fdsize(fd);
	if (sz == NOSIZE) {
		free_config(r);
		return NULL;
	}

	r->cfgdata = rh_malloc(sz+1); /* so last line will not face xmalloc safety zone. */
	x = io_read_data(fd, r->cfgdata, sz, NO, NULL);
	if (x == NOSIZE) {
		free_config(r);
		return NULL;
	}

	x = rh_strlrep(r->cfgdata, x, "\r\n", "\n");
	r->cfgdata = rh_realloc(r->cfgdata, x+1);
	s = r->cfgdata+x; *s = 0;

	r->d = r->cfgdata;
	return (void *)r;
}

char *get_config_line(void *config)
{
	struct config *cfg;
	char *line;

	if (!config) return NULL;
	cfg = config;

_again:
	line = strtok_r(cfg->d, "\n", &cfg->t);
	if (!line) return NULL;
	if (cfg->d) cfg->d = NULL;
	if (is_comment(line)) goto _again;

	return line;
}

void free_config(void *config)
{
	struct config *cfg;

	cfg = config;
	pfree(cfg->cfgdata);
	pfree(cfg);
}
