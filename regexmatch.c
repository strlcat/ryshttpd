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

static void fixup_regex_pattern(char **s)
{
	char *z = *s;
	size_t n = strnlen(z, RH_XSALLOC_MAX);

	if (n && *z == '^' && *(z+n-1) == '$') return;

	z = *s = rh_realloc(z, n+3);
	memmove(z+1, z, n);
	*z = '^';
	*(z+n+1) = '$';
}

static void unfixup_regex_pattern(char *s)
{
	size_t n = strnlen(s, RH_XSALLOC_MAX);

	if (n < 2) return;
	if (n && !(*s == '^' && *(s+n-1) == '$')) return;

	*(s+n-1) = 0;
	memmove(s, s+1, n-1);
}

/*
 * This is a wrapper around host regex
 * to support reentrancy. It also stores
 * errors inside this little struct, so
 * calls to check functions are easy.
 */
struct regex_storage {
	regex_t regex; /* host regex structure, which we do not control */
	regmatch_t *pmatch; /* if pmatch == YES, then this is allocated */

	char *spattern; /* original pattern used to compile */
	int estatus; /* error status, for regerror */
	char *error; /* output error string, which regerror returned */
};

void *regex_compile(const char *pattern, rh_yesno nocase, rh_yesno pmatch, rh_yesno nofixup)
{
	struct regex_storage *rgx;
	int status;

	rgx = rh_malloc(sizeof(struct regex_storage));

	rgx->spattern = rh_strndup(pattern, RH_ALLOC_MAX * 2);
	if (nofixup == NO) fixup_regex_pattern(&rgx->spattern);

	if (pmatch) rgx->pmatch = rh_malloc(sizeof(regmatch_t) * RH_REGEX_MAX_GROUPS);

	status = regcomp(&rgx->regex, rgx->spattern,
		REG_EXTENDED
		| (pmatch == YES ? 0 : REG_NOSUB)
		| (nocase == YES ? REG_ICASE : 0));

	if (status) {
		rgx->estatus = status;
		rgx->error = regex_error(&rgx->regex);
	}

	return (void *)rgx;
}

rh_yesno regex_exec(const void *regex, const char *string)
{
	const struct regex_storage *rgx = regex;

	return regexec(&rgx->regex, string,
		rgx->pmatch ? RH_REGEX_MAX_GROUPS : 0,
		rgx->pmatch, 0) == 0 ? YES : NO;
}

char *regex_get_pattern(const void *regex)
{
	const struct regex_storage *rgx = regex;
	char *r;

	r = rh_strdup(rgx->spattern);
	unfixup_regex_pattern(r);
	return r;
}

char *regex_get_match(const void *regex, const char *string, size_t idx)
{
	const struct regex_storage *rgx = regex;
	const regmatch_t *pmatch;
	size_t n;
	char *r;

	if (!string) return NULL;
	if (!rgx->pmatch) return NULL;
	if (idx > RH_REGEX_MAX_GROUPS) return NULL;

	pmatch = rgx->pmatch+idx;
	if (pmatch->rm_so == (regoff_t)-1) return NULL;
	n = strlen(string);
	if (pmatch->rm_so >= n) return NULL;

	r = rh_malloc((pmatch->rm_eo - pmatch->rm_so) + 1);
	rh_strlcpy_real(r, string + pmatch->rm_so, (pmatch->rm_eo - pmatch->rm_so) + 1);

	return r;
}

rh_yesno regex_is_error(const void *regex)
{
	const struct regex_storage *rgx = regex;

	return rgx->error ? YES : NO;
}

char *regex_error(const void *regex)
{
	size_t x;
	char *errstr;
	const struct regex_storage *rgx = regex;

	if (regex_is_error(regex)) return rgx->error;

	x = regerror(rgx->estatus, &rgx->regex, NULL, 0);
	if (x > RH_ALLOC_SMALL) x = RH_ALLOC_SMALL;
	errstr = rh_malloc(x);
	regerror(rgx->estatus, &rgx->regex, errstr, x);

	return errstr;
}

void regex_xexits(const void *regex)
{
	char *serr;

	serr = regex_error(regex);
	xexits("regcomp: %s", serr);
}

void regex_free(void *regex)
{
	struct regex_storage *rgx = regex;

	if (!regex) return;

	regfree(&rgx->regex);
	pfree(rgx->pmatch);
	pfree(rgx->spattern);
	pfree(rgx->error);
	pfree(rgx);
}
