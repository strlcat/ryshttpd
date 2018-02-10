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

#define DATADEF (unsigned char [])
static const struct embedded_resource rh_resources[] = {
#include "resources.h"
};
#undef DATADEF

const struct embedded_resource *find_resource(int restype, const char *str)
{
	size_t x;

	if (!str || str_empty(str)) return NULL;

	for (x = 0; x < STAT_ARRAY_SZ(rh_resources); x++) {
		switch (restype) {
			case RESTYPE_PATH:
				if (rh_resources[x].path
				&& !strcmp(rh_resources[x].path, str))
					return &rh_resources[x];
				break;
			case RESTYPE_NAME:
				if (rh_resources[x].name
				&& !strcmp(rh_resources[x].name, str))
					return &rh_resources[x];
				break;
			case RESTYPE_ARGS:
				if (rh_resources[x].args
				&& !strcmp(rh_resources[x].args, str))
					return &rh_resources[x];
				break;
			default: return NULL;
		}
	}

	return NULL;
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

void free_resource(struct embedded_resource *rsrc)
{
	pfree(rsrc->path);
	pfree(rsrc->name);
	pfree(rsrc->args);

	pfree(rsrc->mimetype);
	pfree(rsrc->data);

	pfree(rsrc);
}
