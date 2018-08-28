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

#ifndef WITH_LIBMAGIC
struct mime_table {
	const char *fnames; /* regex file names that are matched */
	const char *mime; /* mime string */
	void *rgx_precomp; /* precompiled regex for faster search */
};

#define DEFMIME(s, d) { .fnames = s, .mime = d, },
static struct mime_table rh_mime_table[] = {
#include "mimedb.h"
};
#undef DEFMIME

void init_mime_regex(void)
{
	size_t x;

	for (x = 0; x < STAT_ARRAY_SZ(rh_mime_table); x++) {
		rh_mime_table[x].rgx_precomp = regex_compile(rh_mime_table[x].fnames, YES, NO);
		if (regex_is_error(rh_mime_table[x].rgx_precomp))
			regex_xexits(rh_mime_table[x].rgx_precomp);
	}
}

static const char *match_mime_filename(const char *filename)
{
	size_t x;

	for (x = 0; x < STAT_ARRAY_SZ(rh_mime_table); x++) {
		if (regex_exec(rh_mime_table[x].rgx_precomp, filename) == YES)
			return rh_mime_table[x].mime;
	}

	return NULL;
}
#endif

#ifdef WITH_LIBMAGIC
#include <magic.h>

static magic_t rh_mgct;

rh_yesno init_magic_db(void)
{
	if (!rh_mgct) {
		rh_mgct = magic_open(MAGIC_MIME);
		if (!rh_mgct) return NO;
		if (magic_load(rh_mgct, rh_magicdb_path) == -1)
			return NO;
	}

	return YES;
}

/*
 * You HAVE to provide magic database on the target,
 * because libmagic won't use it's builtins anyway.
 * This is hopefully the only external dependency
 * since it's really hard to provide _accurate_
 * MIME type if file advertises .bin extension but
 * really is text file or any way other.
 *
 * I design my httpd to be reliable and understand
 * it's requirements and I want it to function well.
 */

char *get_mime_fd(int fd, void *tmp, size_t tsz)
{
	const char *result;
	size_t sz;

	sz = (size_t)pread(fd, tmp, tsz, 0);
	if (sz == NOSIZE) return NULL;

	result = magic_buffer(rh_mgct, tmp, sz);
	if (!result) return NULL;

	return rh_strdup(result);
}
#else
char *get_mime_filename(const char *filename)
{
	const char *mime;

	mime = match_mime_filename(filename);
	if (!mime) return NULL;

	if (rh_content_charset
	&& !strncmp(mime, "text/", CSTR_SZ("text/"))) {
		char *r = NULL;
		rh_asprintf(&r, "%s; charset=%s", mime, rh_content_charset);
		return r;
	}

	return rh_strdup(mime);
}
#endif
