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

char *find_index_file(const char *path)
{
	char *r;
	DIR *dp;
	struct dirent *de;

	if (file_or_dir(path) != PATH_IS_DIR) return NULL;

	dp = opendir(path);
	if (!dp) return NULL;

	r = NULL;
	while ((de = readdir(dp))) {
		if (!strcmp(de->d_name, ".")
		|| !strcmp(de->d_name, "..")
		|| strstr(de->d_name, rh_htaccess_name)) continue;

		if (regex_exec(rh_indexes_rgx, de->d_name)) {
			rh_asprintf(&r, "%s/%s", path, de->d_name);
			if (file_or_dir(r) == PATH_IS_FILE) break;
			else pfree(r);
		}
	}

	closedir(dp);
	return r;
}
