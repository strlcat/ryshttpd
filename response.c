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

static const struct response_status rh_responses[] = {
#include "response_codes.h"
};

static const struct response_status *find_response(int status)
{
	size_t x;

	for (x = 0; x < STAT_ARRAY_SZ(rh_responses); x++) {
		if (rh_responses[x].status == status) return &rh_responses[x];
	}

	return NULL;
}

static void *add_to_response(void *rsp, rh_yesno crlf, const void *data, size_t szdata)
{
	void *r = rsp;
	size_t sz;

	r = append_data(r, data, szdata);
	sz = (crlf == YES) ? CSTR_SZ("\r\n") : CSTR_SZ("\n");
	r = append_data(r, (crlf == YES) ? "\r\n" : "\n", sz);

	return r;
}

static void *add_status_line(void *rsp, struct client_state *clstate, const struct response_status *resp)
{
	char *s = NULL;
	size_t x;
	void *r = rsp;

	x = rh_asprintf(&s, "HTTP/%s %s",
		clstate->protoversion ? clstate->protoversion : "0.9", resp->response);
	r = add_to_response(r, clstate->is_crlf, s, x);
	pfree(s);

	return r;
}

static void *add_std_headers(void *rsp, struct client_state *clstate)
{
	char *s, *d, *t;
	size_t x;
	void *r = rsp;

	s = d = NULL;

	t = find_header_value(clstate->sendheaders, "Server");
	x = rh_asprintf(&s, "Server: %s", t ? t : rh_ident);
	if (t) delete_header(&clstate->sendheaders, "Server");
	r = add_to_response(r, clstate->is_crlf, s, x);

	t = find_header_value(clstate->sendheaders, "Date");
	if (!t) d = getsdate(clstate->request_time, HTTP_DATE_FMT, YES);
	x = rh_asprintf(&s, "Date: %s", t ? t : d);
	if (t) delete_header(&clstate->sendheaders, "Date");
	pfree(d);
	r = add_to_response(r, clstate->is_crlf, s, x);

	t = find_header_value(clstate->sendheaders, "Connection");
	x = rh_asprintf(&s, "Connection: %s",
		t ? t : (clstate->is_keepalive ? "keep-alive" : "close"));
	if (t) {
		if (!strcasecmp(t, "close")) {
			clstate->is_keepalive = NO;
			delete_header(&clstate->sendheaders, "Keep-Alive");
			delete_header(&clstate->sendheaders, "Transfer-Encoding");
		}
		delete_header(&clstate->sendheaders, "Connection");
	}
	r = add_to_response(r, clstate->is_crlf, s, x);

	pfree(s);
	return r;
}

static void *add_alt_headers(void *rsp, struct client_state *clstate)
{
	char *s;
	size_t sz, x, z;
	void *r = rsp;

	sz = DYN_ARRAY_SZ(clstate->sendheaders);
	for (x = 0, s = NULL; x < sz; x++) {
		if (!clstate->sendheaders[x].name
		|| !clstate->sendheaders[x].value) continue;
		z = rh_asprintf(&s, "%s: %s",
			clstate->sendheaders[x].name, clstate->sendheaders[x].value);
		r = add_to_response(r, clstate->is_crlf, s, z);
	}

	pfree(s);
	return r;
}

static void io_set_error(struct client_state *clstate, int iostate)
{
	clstate->ioerror = errno;
	clstate->iostate = iostate;
}

void response_chunk_length(struct client_state *clstate, size_t length)
{
	struct client_info *cli = clstate->clinfo;
	char s[20];
	size_t sz;

	/*
	 * Not relevant: we just append data to socket,
	 * and indicate it's length by closing connection.
	 */
	if (clstate->is_keepalive == NO) return;

	sz = rh_snprintf(s, sizeof(s), "%zX", length);
	if (io_send_data(cli, s, sz, NO, NO) == NOSIZE)
		io_set_error(clstate, IOS_WRITE_ERROR);
	else clstate->sentbytes += sz;

	sz = (clstate->is_crlf == YES) ? CSTR_SZ("\r\n") : CSTR_SZ("\n");
	if (io_send_data(cli, (clstate->is_crlf == YES) ? "\r\n" : "\n", sz, NO, NO) == NOSIZE)
		io_set_error(clstate, IOS_WRITE_ERROR);
	else clstate->sentbytes += sz;
}

void response_chunk_end(struct client_state *clstate)
{
	struct client_info *cli = clstate->clinfo;
	size_t sz;

	if (clstate->is_keepalive == NO) return;

	sz = (clstate->is_crlf == YES) ? CSTR_SZ("\r\n") : CSTR_SZ("\n");
	if (io_send_data(cli, (clstate->is_crlf == YES) ? "\r\n" : "\n", sz, NO, NO) == NOSIZE)
		io_set_error(clstate, IOS_WRITE_ERROR);
	else clstate->sentbytes += sz;
}

void response_error(struct client_state *clstate, int status)
{
	struct client_info *cli = clstate->clinfo;
	const struct response_status *rsp;
	const struct embedded_resource *rsrc;
	struct embedded_resource *drsrc;
	struct fmtstr_args *fsa = NULL;
	size_t nr_fsa = 0, sz;
	struct fmtstr_state fst;
	char *s, *errdata = NULL;
	void *rspdata = NULL;

	rsp = find_response(status);
	if (!rsp) rsp = find_response(500);
	s = NULL;
	rh_asprintf(&s, "error%d.html", status);
	rsrc = find_resource(RESTYPE_NAME, s);
	if (!rsrc) rsrc = find_resource(RESTYPE_NAME, "error.html");
	pfree(s);

	if (clstate->prepend_path) {
		drsrc = clone_resource(rsrc);
		if (resource_prepend_path(drsrc, clstate->prepend_path) == NO)
			free_resource(drsrc);
		else rsrc = drsrc;
	}
	else drsrc = NULL;

	/* drop client if 400 or 500 error. */
	if (status == 400 || status == 500) {
		clstate->is_keepalive = NO;
		delete_header(&clstate->sendheaders, "Keep-Alive");
	}

	/*
	 * Parse error body template.
	 * From the first start it should fit the space.
	 */
	sz = (rsrc->szdata / 2) * 3;
	s = rh_memdup(rsrc->data, rsrc->szdata);
	s = rh_realloc(s, rsrc->szdata+1);
_tryagain:
	errdata = rh_realloc(errdata, sz);
	APPEND_FSA(fsa, nr_fsa, "RH_ERROR_STR", 0, "%s", rsp->response);
	APPEND_FSA(fsa, nr_fsa, "RH_IDENT_STR", 0, "%s", rh_ident);
	APPEND_FSA(fsa, nr_fsa, "RH_DATE_STR", 0, "%s", clstate->request_date);
	rh_memzero(&fst, sizeof(struct fmtstr_state));
	fst.args = fsa;
	fst.nargs = nr_fsa;
	fst.fmt = s;
	fst.result = errdata;
	fst.result_sz = rh_szalloc(errdata);
	parse_fmtstr(&fst);
	pfree(fsa);
	if (fst.trunc) {
		sz += rsrc->szdata;
		if (sz > RH_XSALLOC_MAX) xexits("bad errdata parse state");
		goto _tryagain;
	}
	pfree(s);

	/* Cleanup of double slashes in paths (FIXME) */
	rh_strlrep(errdata, rh_szalloc(errdata), "//", "/");
	/* shrink it so the Content-Length size is actual */
	sz = shrink_dynstr(&errdata);
	if (sz > 0) sz--;

	/* Add length indicator */
	s = NULL;
	rh_asprintf(&s, "%zu", sz);
	add_header(&clstate->sendheaders, "Content-Length", s);
	pfree(s);
	/* Add error page mime type header */
	add_header(&clstate->sendheaders, "Content-Type", rsrc->mimetype);

	/* Log response status code */
	rh_asprintf(&clstate->status, "%u", status);

	/* add "HTTP/1.0 404 Not Found" style line */
	rspdata = add_status_line(rspdata, clstate, rsp);

	/* add core server headers */
	rspdata = add_std_headers(rspdata, clstate);
	/* add accumulated headers */
	rspdata = add_alt_headers(rspdata, clstate);

	/* add final "\r\n" indicating end of head. */
	rspdata = add_to_response(rspdata, clstate->is_crlf, NULL, 0);

	/* add error message page */
	rspdata = append_data(rspdata, errdata, sz);
	/* count error message bytes only */
	clstate->sentbytes += sz;

	/* Send the response */
	if (io_send_data(cli, rspdata, rh_szalloc(rspdata), NO, YES) == NOSIZE)
		io_set_error(clstate, IOS_WRITE_ERROR);

	pfree(rspdata);
	pfree(errdata);
	if (drsrc) free_resource(drsrc);
}

void response_ok(struct client_state *clstate, int status, rh_yesno end_head)
{
	struct client_info *cli = clstate->clinfo;
	const struct response_status *rsp;
	void *rspdata = NULL;

	rsp = find_response(status);
	if (!rsp) {
		response_error(clstate, 500);
		return;
	}

	/* Log response status code */
	rh_asprintf(&clstate->status, "%u", status);

	/* add successive status line */
	rspdata = add_status_line(rspdata, clstate, rsp);

	/* add core server headers */
	rspdata = add_std_headers(rspdata, clstate);
	/* add accumulated headers. See client.c source. */
	rspdata = add_alt_headers(rspdata, clstate);
	/*
	 * A CGI exec may append it's own, custom headers.
	 * If so, do not end head prematurely.
	 * It's now the task of exec to continue with response.
	 */
	if (end_head == YES)
		rspdata = add_to_response(rspdata, clstate->is_crlf, NULL, 0);

	/* Send the response */
	if (io_send_data(cli, rspdata, rh_szalloc(rspdata), NO, YES) == NOSIZE)
		io_set_error(clstate, IOS_WRITE_ERROR);

	pfree(rspdata);
}

size_t response_recv_data(struct client_state *clstate, void *data, size_t szdata)
{
	struct client_info *cli = clstate->clinfo;
	size_t recvd;

	recvd = io_recv_data(cli, data, szdata, YES, NO);
	if (recvd == NOSIZE) io_set_error(clstate, IOS_READ_ERROR);
	else clstate->recvbytes += recvd;
	return recvd;
}

void response_send_data(struct client_state *clstate, const void *data, size_t szdata)
{
	struct client_info *cli = clstate->clinfo;
	size_t sent;

	sent = io_send_data(cli, data, szdata, NO, NO);
	if (sent == NOSIZE) io_set_error(clstate, IOS_WRITE_ERROR);
	else clstate->sentbytes += sent;
}
