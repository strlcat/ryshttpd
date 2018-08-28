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

/* special version of parse_escapes */
void urldecode(char *str, size_t n)
{
	char chr[2], spec[4], *s, *d;

	if (!str || str_empty(str)) return;

	s = str;
	while (1) {
		d = strchr(s, '%');
		if (!d) break;
		rh_strlcpy_real(spec, d, sizeof(spec));
		if (!strcmp(spec, "%25")) { /* skip percents, replace 'em later */
			s = d+CSTR_SZ("%25");
			goto _cont;
		}
		if (!isxdigit(spec[2])) spec[2] = 0;
		if (!getxchr(chr, spec+1)) {
			s = d+1;
			goto _cont;
		}
		rh_strlrep(str, n, spec, chr);
_cont:		if (s-str >= n) break;
	}
	rh_strlrep(str, n, "%25", "%");
}

char *urlencode(const char *str)
{
	const char *s = str;
	char t[12], *r = NULL;

	if (!str || str_empty(str)) return rh_strdup("");

	while (*s) {
		if (!isalnum(*s)
		&& *s != '_' && *s != '-'
		&& *s != '.' && *s != '~') {
			rh_snprintf(t, sizeof(t), "%%%02X", *s);
			rh_astrcat(&r, t);
		}
		else {
			t[0] = *s;
			t[1] = 0;
			rh_astrcat(&r, t);
		}
		s++;
	}

	return r;
}
