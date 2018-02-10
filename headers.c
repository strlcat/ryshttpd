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

struct http_header *parse_headers(char *const *headers, size_t start, size_t end)
{
	size_t sz, x, y;
	char *s, *d;
	struct http_header *hdrlist;

	x = start;
	sz = DYN_ARRAY_SZ(headers);
	hdrlist = NULL;
	if (end == 0) end = sz;

	if (start >= end) return NULL;

	do {
		s = rh_strdup(headers[x]);

		d = strchr(s, ':');
		if (!d) goto _bad;
		*d = 0; d++;
		while (*d == ' ') d++;
		y = DYN_ARRAY_SZ(hdrlist);
		hdrlist = rh_realloc(hdrlist, (y+1) * sizeof(struct http_header));
		if (!find_header(hdrlist, s)) { /* save only first version */
			hdrlist[y].name = rh_strdup(s);
			hdrlist[y].value = rh_strdup(d);
		}

_bad:		pfree(s);
		x++;
	} while (x < end);

	return hdrlist;
}

void add_header(struct http_header **hdrlist, const char *name, const char *value)
{
	size_t sz;
	struct http_header *hdr;

	hdr = find_header(*hdrlist, name);
	if (hdr) {
		pfree(hdr->name);
		pfree(hdr->value);
		hdr->name = rh_strdup(name);
		hdr->value = rh_strdup(value);
		return;
	}

	hdr = *hdrlist;
	sz = DYN_ARRAY_SZ(hdr);
	hdr = rh_realloc(hdr, (sz+1) * sizeof(struct http_header));
	hdr[sz].name = rh_strdup(name);
	hdr[sz].value = rh_strdup(value);
	*hdrlist = hdr;
}

void delete_header(struct http_header **hdrlist, const char *name)
{
	struct http_header *hdr;

	hdr = find_header(*hdrlist, name);
	if (hdr) {
		pfree(hdr->name);
		pfree(hdr->value);
	}
}

struct http_header *find_header(struct http_header *hdrlist, const char *name)
{
	size_t sz, x;

	sz = DYN_ARRAY_SZ(hdrlist);
	for (x = 0; x < sz; x++) {
		if (hdrlist[x].name
		&& !strcasecmp(name, hdrlist[x].name)) return &hdrlist[x];
	}
	return NULL;
}

char *find_header_value(struct http_header *hdrlist, const char *name)
{
	struct http_header *found;

	found = find_header(hdrlist, name);
	if (found) return found->value;
	return NULL;
}

size_t headers_fmtstr_parse(struct http_header *hdrlist, char *line, size_t szline, const char *rpl)
{
	char *bs, *s, *d, *t;
	char *fmt, *name;
	const char *data;
	size_t n;

	n = strnlen(line, szline);
	if (!is_fmtstr(line)) return n;

	d = line; name = fmt = NULL;
	while (1) {
		bs = s = strstr(d, "%{hdr_");
		if (!s) break;
		t = s + CSTR_SZ("%{hdr_");
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
			s += CSTR_SZ("%{hdr_");
			name = rh_realloc(name, t-s+1);
			rh_strlcpy_real(name, s, t-s+1);
		}

		data = find_header_value(hdrlist, name);
		if (!data) {
			rh_strrep(name, "_", "-");
			data = find_header_value(hdrlist, name);
		}
		if (!data) data = rpl;
		n = rh_strlrep(line, szline, fmt, data);
		if (n >= szline) break;
		d = bs + (data ? strlen(data) : 0);
	}

	pfree(fmt);
	pfree(name);

	return n;
}
