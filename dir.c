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

char *rh_realpath(const char *path)
{
	char *r, *s, *dir;

	dir = rh_malloc(PATH_MAX);
	s = realpath(path, dir);
	if (!s) {
		pfree(dir);
		return NULL;
	}

	r = rh_strdup(s);
	pfree(dir);
	return r;
}

rh_yesno is_symlink(const char *path)
{
	struct stat st;

	rh_memzero(&st, sizeof(struct stat));
	if (lstat(path, &st) == -1) return NO;
	if (S_ISLNK(st.st_mode)) return YES;
	return NO;
}

int file_or_dir(const char *path)
{
	struct stat st;

	rh_memzero(&st, sizeof(struct stat));
	if (stat(path, &st) == -1) return -1;
	if (S_ISDIR(st.st_mode)) return PATH_IS_DIR;
	return PATH_IS_FILE;
}

rh_yesno is_exec(const char *path)
{
	errno = 0;
	if ((file_or_dir(path) == PATH_IS_FILE) && !errno) {
		if ((access(path, X_OK) == 0) && !errno) return YES;
	}
	return NO;
}
