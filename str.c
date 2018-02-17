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

rh_yesno str_empty(const char *str)
{
	if (!*str) return YES;
	return NO;
}

size_t char_to_nul(char *s, size_t l, char c)
{
	char *os = s;
	int found = 0;

	while (*s && l) {
		if (*s == c) {
			*s = 0;
			found = 1;
			break;
		}
		s++;
		l--;
	}
	return found ? s-os : NOSIZE;
}

size_t rh_strlcpy(char *d, const char *s, size_t n)
{
	size_t x;

	x = rh_strlcpy_real(d, s, n);
	if (x >= n) xexits("rh_strlcpy complains that data is truncated.");
	return x;
}

rh_yesno is_fmtstr(const char *s)
{
	if (!s || str_empty(s)) return NO;
	if (strstr(s, "%{") && strchr(s, '}')) return YES;
	return NO;
}

void nuke_fmtstr_templates(char *line, size_t szline)
{
	char *fmt, *s, *d, *t;

	s = d = line; fmt = NULL;
	while (1) {
		s = strchr(d, '%');
		if (!s) break;
		if (s && *(s+1) != '{') break;
		t = s;
		while (*t && (*t != '}' && *t != ' ')) t++;
		if (*t != '}') {
			d = t;
			continue;
		}
		else {
			t += CSTR_SZ("}");
			fmt = rh_realloc(fmt, t-s+1);
			rh_strlcpy_real(fmt, s, t-s+1);
		}

		rh_strlrep(line, szline, fmt, NULL);
		d = s;
	}

	pfree(fmt);
}

char *parse_fmtstr(struct fmtstr_state *fst)
{
	struct fmtstr_args *args = fst->args;
	int nargs = fst->nargs;
	const char *fmt = fst->fmt;
	char *out = fst->result;
	size_t outl = fst->result_sz;
	char *s, *d;
	size_t n;
	int x, f;

	if (!is_fmtstr(fmt)) {
		/* get slack and never do the useless hard job */
		rh_strlcpy(out, fmt, outl);
		fst->nr_parsed = 0;
		return out;
	}

	rh_strlcpy(out, fmt, outl);

	s = d = NULL;
	for (x = 0; x < nargs
	&& (args+x)
	&& (args+x)->spec; x++) {
		rh_asprintf(&s, "%%{%s}", (args+x)->spec);
		if (!strstr(fmt, s)) continue; /* not found - get slack now! */

		switch ((args+x)->size) {
			case 1: rh_asprintf(&d, (args+x)->fmt, *(uint8_t *)(args+x)->data); break;
			case 2: rh_asprintf(&d, (args+x)->fmt, *(uint16_t *)(args+x)->data); break;
			case 4: rh_asprintf(&d, (args+x)->fmt, *(uint32_t *)(args+x)->data); break;
			case 8: rh_asprintf(&d, (args+x)->fmt, *(uint64_t *)(args+x)->data); break;
			default: rh_asprintf(&d, (args+x)->fmt,
				(args+x)->data ? (args+x)->data : "");
				break;
		}

		f = -1;
		n = rh_strltrep(out, outl, &f, s, d);
		if (n >= outl) {
			fst->trunc = 1;
			break;
		}
		if (f > 0) fst->nr_parsed++;
	}

	pfree(s);
	pfree(d);

	return out;
}

size_t shrink_dynstr(char **s)
{
	size_t x;

	if (!s) return NOSIZE;
	if (!*s) return NOSIZE;
	if (str_empty(*s)) return 0;

	x = strnlen(*s, RH_XSALLOC_MAX)+1;
	*s = rh_realloc(*s, x);
	return x;
}

void rh_astrcat(char **d, const char *s)
{
	size_t dn, sn, t;
	char *dd;

	if (!s || !d) return;
	if (!*d) {
		*d = rh_strdup(s);
		return;
	}

	dd = *d;
	sn = strnlen(s, RH_XSALLOC_MAX);
	dn = t = shrink_dynstr(&dd);
	if (t > 0) t--;
	dn += sn+1;
	dd = rh_realloc(dd, dn);
	rh_strlcpy(dd+t, s, sn+1);
	*d = dd;
}

void rh_prepend_str(char **d, const char *s)
{
	char *t, *T;

	if (!s || !d) return;
	t = rh_strdup(s);
	if (!*d) {
		*d = t;
		return;
	}

	T = *d;
	rh_astrcat(&t, T);
	*d = t;
	pfree(T);
}

int rh_snprintf(char *s, size_t n, const char *fmt, ...)
{
	int r;
	va_list ap;
	va_start(ap, fmt);
	r = rh_vsnprintf(s, n, fmt, ap);
	va_end(ap);
	return r;
}

static int rh_vsnprintf_real(char *s, size_t n, const char *fmt, va_list ap)
{
	int r;
	va_list t;

	va_copy(t, ap);
	r = vsnprintf(s, n, fmt, t);
	va_end(t);
	return r;
}

int rh_vsnprintf(char *s, size_t n, const char *fmt, va_list ap)
{
	int r;
	va_list t;

	va_copy(t, ap);
	r = rh_vsnprintf_real(s, n, fmt, t);
	va_end(t);
	if (r < 0) xerror("rh_vsnprintf");
	else if (r >= n) xerror("rh_vsnprintf");

	return r;
}

int rh_vasprintf(char **s, const char *fmt, va_list ap)
{
	int r;
	size_t n;
	va_list t;

	if (!*s) {
		n = RH_ALLOC_SMALL;
		*s = rh_malloc(n);
	}
	else n = rh_szalloc(*s);

	va_copy(t, ap);
	r = rh_vsnprintf_real(*s, n, fmt, t);
	va_end(t);
	if (r == -1) return -1;
	if (r >= n) {
		n = (size_t)r+1;
		*s = rh_realloc(*s, n);

		va_copy(ap, t);
		r = rh_vsnprintf_real(*s, n, fmt, t);
		va_end(t);
		if (r == -1) return -1;
	}

	return r;
}

int rh_asprintf(char **s, const char *fmt, ...)
{
	int r;
	va_list ap;

	va_start(ap, fmt);
	r = rh_vasprintf(s, fmt, ap);
	if (r == -1) xerror("rh_asprintf");
	va_end(ap);

	return r;
}

rh_yesno getxchr(char *chr, const char *s)
{
	unsigned long x;
	char *p;

	if (!s || str_empty(s)) return NO;
	chr[1] = 0;
	x = strtoul(s, &p, 16);
	if (str_empty(p)) {
		chr[0] = (unsigned char)x;
		return YES;
	}
	return NO;
}

void parse_escapes(char *str, size_t n)
{
	char chr[2], spec[5], *s, *d;

	if (!str || str_empty(str)) return;
	if (!strchr(str, '\\')) return;

	rh_strlrep(str, n, "\\n", "\n");
	rh_strlrep(str, n, "\\r", "\r");
	rh_strlrep(str, n, "\\t", "\t");

	s = str;
	while (1) {
		d = strstr(s, "\\x");
		if (!d) break;
		rh_strlcpy_real(spec, d, sizeof(spec));
		if (!isxdigit(spec[3])) spec[3] = 0;
		if (!getxchr(chr, spec+2)) goto _cont;
		rh_strlrep(str, n, spec, chr);
_cont:		s = d+1;
		if (s-str >= n) break;
	}
}

static size_t remove_strings(char *str, size_t strsz, ...)
{
	size_t n, x;
	va_list ap;

	va_start(ap, strsz);
	for (n = 0; va_arg(ap, const char *); n++);
	va_end(ap);
	va_start(ap, strsz);
	for (x = 0; x < n; x++) rh_strlrep(str, strsz, va_arg(ap, const char *), NULL);
	va_end(ap);

	return strnlen(str, strsz);
}

size_t filter_dotdots(char *str, size_t strsz)
{
	size_t n;

	/* It does not tries to translate paths. It just does cleanup. */
	rh_strlrep(str, strsz, "//", "/");
	n = remove_strings(str, strsz, "../", "/../", "./", "/./", "/..", NULL);

	if (n > 1 && str[n-1] == '/') {
		n--;
		str[n] = 0;
	}

	return n;
}

void unquote(char *str, size_t strsz)
{
	size_t n = strnlen(str, strsz);

	if (n < 2) return;
	if (n && !(*str == '"' && *(str+n-1) == '"')) return;

	*(str+n-1) = 0;
	memmove(str, str+1, n-1);
}
