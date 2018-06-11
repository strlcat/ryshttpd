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

/*
 * Embedded resources: images, style sheets to decorate
 * pages, and maybe some secret pages of course ;-)
 *
 * They are nonmdifiable things! If you wish to alter it,
 * then please clone it and alter in a new memory space.
 *
 * They served as is:
 * - No support for partial transfers for them,
 * - Mime type is hardcoded and not queried,
 * - Always present, so even if real file exists
 *   on same path, it will be never sent but a resource instead.
 * Hopefully there will be not as much of them, so
 * they will not waste too much space inside httpd.
 *
 * Error page(s) are here too, but they're preparsed before being sent,
 * and they are special case anyway. They are hidden by having "name"
 * instead of "path", so they are not shared outside by this query,
 * only when error happened and response_error function parsed and emitted it.
 */

static const struct embedded_resource rh_resources[] = {
#include "resources.h"
};

static struct embedded_resource *rh_user_resources;

static const struct embedded_resource *do_find_resource(
	const struct embedded_resource *rsrcp, size_t rsrcsz, int restype, const char *str)
{
	size_t x;

	if (!str || str_empty(str)) return NULL;
	if (rsrcsz == 0) return NULL;

	for (x = 0; x < rsrcsz; x++) {
		switch (restype) {
			case RESTYPE_PATH:
				if (rsrcp[x].path
				&& !strcmp(rsrcp[x].path, str))
					return &rsrcp[x];
				break;
			case RESTYPE_NAME:
				if (rsrcp[x].name
				&& !strcmp(rsrcp[x].name, str))
					return &rsrcp[x];
				break;
			case RESTYPE_ARGS:
				if (rsrcp[x].args
				&& !strcmp(rsrcp[x].args, str))
					return &rsrcp[x];
				break;
			default: return NULL;
		}
	}

	return NULL;
}

const struct embedded_resource *find_resource(int restype, const char *str)
{
	const struct embedded_resource *rsrcp, *r;
	size_t sz;

	rsrcp = rh_user_resources;
	sz = DYN_ARRAY_SZ(rh_user_resources);
	r = do_find_resource(rsrcp, sz, restype, str);
	if (r) return r;

	rsrcp = rh_resources;
	sz = STAT_ARRAY_SZ(rh_resources);
	r = do_find_resource(rsrcp, sz, restype, str);
	return r;
}

const struct embedded_resource *find_resource_args(const char *path, const char *args)
{
	const struct embedded_resource *rsrc;

	rsrc = find_resource(RESTYPE_PATH, path);
	if (rsrc && !rsrc->args) return rsrc;
	rsrc = find_resource(RESTYPE_ARGS, args);
	if (rsrc) return rsrc;

	return NULL;
}

struct embedded_resource *clone_resource(const struct embedded_resource *rsrc)
{
	struct embedded_resource *r;

	r = rh_malloc(sizeof(struct embedded_resource));

	if (rsrc->path) r->path = rh_strdup(rsrc->path);
	if (rsrc->name) r->name = rh_strdup(rsrc->name);
	if (rsrc->args) r->name = rh_strdup(rsrc->name);

	r->mimetype = rh_strdup(rsrc->mimetype);
	r->lastmod = rsrc->lastmod;
	r->szdata = rsrc->szdata;
	r->data = rh_memdup(rsrc->data, rsrc->szdata);

	return r;
}

rh_yesno resource_prepend_path(struct embedded_resource *rsrc, const char *ppath)
{
	char *s = NULL;
	size_t z, n;
	int x;

	n = z = strnlen(ppath, RH_ALLOC_MAX);
	if (n == 0) return NO;

	if (rsrc->path) {
		rh_asprintf(&s, "%s/%s", ppath, rsrc->path);
		shrink_dynstr(&s);
		pfree(rsrc->path);
		rsrc->path = s;
	}

	n *= 2;
	n += rh_szalloc(rsrc->data)+1;
	s = NULL;
	rh_asprintf(&s, "href=\"%s", ppath);
_extend:
	rsrc->data = rh_realloc(rsrc->data, n);
	x = 2;
	if (rh_strltrep(rsrc->data, n, &x, "href=\"/", s) >= n) {
		n += z;
		if (n > RH_XSALLOC_MAX) {
			pfree(s);
			return NO;
		}
		goto _extend;
	}
	pfree(s);

	s = rsrc->data;
	rsrc->szdata = shrink_dynstr(&s);
	rsrc->data = s;
	if (rsrc->szdata > 0) rsrc->szdata--;

	return YES;
}

static void do_free_resource(struct embedded_resource *rsrc)
{
	pfree(rsrc->path);
	pfree(rsrc->name);
	pfree(rsrc->args);
	pfree(rsrc->mimetype);
	pfree(rsrc->data);
}

void free_resource(struct embedded_resource *rsrc)
{
	do_free_resource(rsrc);
	pfree(rsrc);
}

rh_yesno load_user_resource(
	const char *resfpath, const char *htpath, const char *name,
	const char *htargs, const char *mimetype)
{
	int fd;
	rh_yesno filesz;
	size_t sz;
	struct stat stst;

	if (!strncmp(resfpath, "<text>", CSTR_SZ("<text>"))) {
		fd = -1;
		resfpath += CSTR_SZ("<text>");
		filesz = (rh_fsize)strlen(resfpath);
		goto _textres;
	}

	fd = open(resfpath, O_RDONLY);
	if (fd == -1) return NO;

	if (fstat(fd, &stst) == -1) {
		close(fd);
		return NO;
	}

	filesz = rh_fdsize(fd);
	if (filesz == NOFSIZE) {
		close(fd);
		return NO;
	}
	if (filesz != (rh_fsize)stst.st_size) {
		close(fd);
		return NO;
	}

_textres:
	sz = DYN_ARRAY_SZ(rh_user_resources);
	rh_user_resources = rh_realloc(rh_user_resources, (sz+1) * sizeof(struct embedded_resource));
	if (strcmp(htpath, "<null>") != 0) rh_user_resources[sz].path = rh_strdup(htpath);
	rh_user_resources[sz].name = rh_strdup(name);
	if (strcmp(htargs, "<null>") != 0) rh_user_resources[sz].args = rh_strdup(htargs);
	rh_user_resources[sz].mimetype = rh_strdup(mimetype);
	rh_user_resources[sz].is_static = NO;
	rh_user_resources[sz].lastmod = stst.st_mtime;

	rh_user_resources[sz].szdata = (size_t)filesz;
	rh_user_resources[sz].data = rh_malloc(rh_user_resources[sz].szdata+1);

	if (fd == -1) {
		rh_strlcpy(rh_user_resources[sz].data, resfpath, rh_user_resources[sz].szdata+1);
		parse_escapes(rh_user_resources[sz].data, rh_user_resources[sz].szdata+1);
		return YES;
	}

	if (io_read_data(fd, rh_user_resources[sz].data, rh_user_resources[sz].szdata, NO, NULL) == NOSIZE) {
		do_free_resource(&rh_user_resources[sz]);
		sz = DYN_ARRAY_SZ(rh_user_resources);
		rh_user_resources = rh_realloc(rh_user_resources, (sz-1) * sizeof(struct embedded_resource));
		close(fd);
		return NO;
	}

	close(fd);
	return YES;
}
