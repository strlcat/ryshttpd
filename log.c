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

static void filter_logline(char *logline)
{
	size_t sz, x;
	char chr[2], schr[8];

	sz = rh_szalloc(logline);
	if (sz == 0) return;

	chr[1] = 0;
	for (x = 1; x < 32; x++) {
_last:		chr[0] = (char)x;
		rh_snprintf(schr, sizeof(schr), "\\x%02zx", x);
		if (strchr(logline, x)) {
			if (rh_strlxstr(logline, sz, chr, schr) >= sz)
				rh_strlxstr(logline, sz, chr, ".");
		}
		if (x == 127) return;
	}

	x = 127;
	goto _last;
}

void write_log_line(struct client_state *clstate)
{
	struct client_info *cli = clstate->clinfo;
	size_t x, sz;
	char *logline;
	struct fmtstr_args *fsa;
	size_t nr_fsa;
	struct fmtstr_state fst;

	if (cli->logfd == -1) return;

	if (clstate->altlogline) {
		logline = clstate->altlogline;
		goto _write;
	}

	sz = RH_ALLOC_MAX;
	logline = rh_malloc(sz);

	preset_fsa(&fsa, &nr_fsa, clstate);

_again:	rh_memzero(&fst, sizeof(struct fmtstr_state));
	fst.args = fsa;
	fst.nargs = nr_fsa;
	fst.fmt = rh_logfmt;
	fst.result = logline;
	fst.result_sz = sz;
	parse_fmtstr(&fst);
	if (fst.trunc) {
		sz += RH_ALLOC_SMALL;
		if (sz > RH_XSALLOC_MAX) xexits("bad logfmt parse state");
		logline = rh_realloc(logline, sz);
		goto _again;
	}
	pfree(fsa);

_again2:
	if (headers_fmtstr_parse(clstate->headers, logline, sz, "-") >= sz) {
		sz += RH_ALLOC_SMALL;
		if (sz > RH_XSALLOC_MAX) xexits("bad logfmt parse state");
		logline = rh_realloc(logline, sz);
		goto _again2;
	}

_write:
	filter_logline(logline);
	sz = shrink_dynstr(&logline);
	if (sz < 2 || sz == NOSIZE) xexits("logline too short");
	logline[sz-1] = '\n'; /* do not use logline as C str after this line!! */

	x = xwrite(cli->logfd, logline, sz);
	if (x == NOSIZE) {
		int sve = errno;

		xwrite(1, logline, sz);
		errno = sve;
		xerror("writing log line");
	}
	/* Write succeeded! */
	if (cli->maxlogsz != NOSIZE) cli->logwrit += x;

	if (!clstate->altlogline) pfree(logline);
	else clstate->altlogline = logline;
}
