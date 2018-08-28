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

struct http_arg *parse_args(const char *args)
{
	char *s, *ss, *d, *t;
	size_t sz;
	struct http_arg *aargs = NULL;

	s = d = rh_strdup(args); t = NULL;
	while ((s = strtok_r(d, "&", &t))) {
		if (d) d = NULL;
		if (str_empty(s)) continue;
		ss = strchr(s, '=');
		if (ss) {
			*ss = 0;
			ss++;
		}
		sz = DYN_ARRAY_SZ(aargs);
		aargs = rh_realloc(aargs, (sz+1) * sizeof(struct http_arg));
		aargs[sz].name = rh_strdup(s);
		if (ss) aargs[sz].value = rh_strdup(ss);
	}

	pfree(s);

	return aargs;
}

struct http_arg *find_arg(struct http_arg *args, const char *name)
{
	size_t sz, x;

	sz = DYN_ARRAY_SZ(args);
	for (x = 0; x < sz; x++) {
		if (args[x].name
		&& !strcmp(name, args[x].name)) return &args[x];
	}
	return NULL;
}

char *find_arg_value(struct http_arg *args, const char *name)
{
	struct http_arg *found;

	found = find_arg(args, name);
	if (found) return found->value;
	return NULL;
}

size_t args_fmtstr_parse(struct http_arg *args, char *line, size_t szline, const char *rpl)
{
	char *bs, *s, *d, *t;
	char *fmt, *name;
	const char *data;
	size_t n;

	n = strnlen(line, szline);
	if (!is_fmtstr(line)) return n;

	d = line; name = fmt = NULL;
	while (1) {
		bs = s = strstr(d, "%{arg_");
		if (!s) break;
		t = s + CSTR_SZ("%{arg_");
		while (*t && (*t != '}' && *t != ' ')) t++;
		if (*t != '}') {
			d = t;
			continue;
		}
		else {
			t += CSTR_SZ("}");
			fmt = rh_realloc(fmt, t-s+1);
			rh_strlcpy_real(fmt, s, t-s+1);
			t -= CSTR_SZ("}");
			s += CSTR_SZ("%{arg_");
			name = rh_realloc(name, t-s+1);
			rh_strlcpy_real(name, s, t-s+1);
		}

		data = find_arg_value(args, name);
		if (!data) data = rpl;
		n = rh_strlrep(line, szline, fmt, data);
		if (n >= szline) break;
		d = bs + (data ? strlen(data) : 0);
	}

	pfree(fmt);
	pfree(name);

	return n;
}
