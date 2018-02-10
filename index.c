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

static char **indexes;

void init_indexes(const char *idxstr)
{
	char *T = rh_strdup(idxstr);
	char *s, *d, *t;
	size_t sz;

	if (indexes) return;

	s = d = T; t = NULL;
	while ((s = strtok_r(d, ":", &t))) {
		if (d) d = NULL;

		sz = DYN_ARRAY_SZ(indexes);
		indexes = rh_realloc(indexes, (sz+1) * sizeof(char *));
		indexes[sz] = rh_strdup(s);
	}

	pfree(T);
}

char *find_index_file(const char *dir)
{
	size_t sz, x;
	char *r;

	if (file_or_dir(dir) != PATH_IS_DIR) return NULL;

	sz = DYN_ARRAY_SZ(indexes);
	for (x = 0, r = NULL; x < sz; x++) {
		rh_asprintf(&r, "%s/%s", dir, indexes[x]);
		if (file_or_dir(r) == PATH_IS_FILE) return r;
	}

	pfree(r);
	return NULL;
}
