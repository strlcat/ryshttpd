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

/*
 * strrep - replace substrings inside strings.
 * (Should be) Safe version written for access(8).
 * Supports counting and limiting number of replacements.
 *
 * -- Rys, 28Sep2017.
 */

#include "httpd.h"

size_t rh_strltrep(char *str, size_t n, int *nr_reps, const char *from, const char *to)
{
	size_t sl, fl, tl, step;
	int l_nr_reps;
	char *s, *d;

	sl = strnlen(str, n);
	if (sl == 0 || sl == n) goto _err;

	fl = strlen(from);
	if (fl == 0) goto _err;
	if (!to) {
		to = "";
		tl = 0;
	}
	else tl = strlen(to);

	/* This does not make sense */
	if (fl == tl && !strcmp(from, to)) goto _err;
	/*
	 * Replacing "amp" with "kiloampere" will still leave "amp"
	 * inside the replaced string, which will trigger another
	 * replace and over and over... prevent that by jumping to
	 * the end of the substituted string so replacement occurs
	 * only once and not recursively.
	 */
	if (tl > fl) step = tl;
	else step = 0;

	l_nr_reps = 0; d = str;
	while (1) {
		if (nr_reps && *nr_reps != -1 && l_nr_reps >= *nr_reps) break;
		s = strstr(d, from);
		if (!s) break;
		d = s + step;
		if (tl == fl) memcpy(s, to, tl);
		else if (tl < fl) {
			memcpy(s, to, tl);
			memmove(s+tl, s+fl, sl-(s-str)-fl);
			memset(s+(sl-(s-str)-fl+tl), 0, fl);
			sl -= (fl-tl);
			if (sl < tl) break;
		}
		else if (tl > fl) {
			sl += (tl-fl);
			/* resized str does not fit - fail. */
			if (sl >= n) break;
			memmove(s+tl, s+fl, sl-(s-str)-tl);
			memcpy(s, to, tl);
		}
		l_nr_reps++;
	}

	if (nr_reps) *nr_reps = l_nr_reps;
	if (l_nr_reps && sl < n) str[sl] = '\0';
	/* return new string length, ceil to size if does not fit */
_err:	return sl > n ? n : sl;
}

size_t rh_strlrep(char *str, size_t n, const char *from, const char *to)
{
	return rh_strltrep(str, n, NULL, from, to);
}

size_t rh_strrep(char *str, const char *from, const char *to)
{
	size_t x = strlen(str)+1;
	size_t y = rh_strltrep(str, x, NULL, from, to);
	return y == x ? x-1 : y;
}
