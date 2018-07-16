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

static char *client_read_pool;
static struct client_state *clstate;

static rh_yesno verify_ascii(const char *str, size_t maxl)
{
	const char *s = str;

	while (s-str < maxl) {
		if (!*s) return NO;
		if (!isprint(*s)
		&& !isascii(*s)
		&& !isspace(*s)) return NO;
		s++;
	}

	return YES;
}

/*
 * ryshttpd always parses Unix (LF) line endings of text requests.
 * The point is that this function gives verdict about what line endings
 * the client is talking in, and both LF and CRLF are supported (but not CR).
 * It also verifies the request to be ASCII clean (at least urlencoded).
 */
static size_t read_raw_request(
	struct client_info *cli, char *to, size_t tol, rh_yesno *crlf,
	char **tail, size_t *sztail)
{
	size_t x, y, z;
	char *pblk, *s;

	if (!to || tol < 1) return NOSIZE;
	rh_memzero(to, tol);

	z = tol-1; pblk = to;
	while (1) {
		x = io_recv_data(cli, pblk, z, YES, YES);
		if (x == 0) break;
		if (x == NOSIZE) return NOSIZE;

		pblk += x; z -= x;
		if (pblk-to >= tol) return 0;

		/* Find CRLF */
		y = CSTR_SZ("\r\n\r\n");
		s = strstr(to, "\r\n\r\n");
		if (s) {
			/* Verify to be ASCII clean/urlencoded */
			if (!verify_ascii(to, s-to)) continue;
			/* That's CRLF request */
			*crlf = YES;
			/*
			 * Win +2 NUL bytes so that strlrep will not fail.
			 * ryshttpd works with LF only anyway.
			 */
			rh_memzero(s, y);
			memcpy(s, "\n\n", CSTR_SZ("\n\n"));
			/* Rewind to end of request */
			s += y;
			/* If it overflows then reject it */
			if (s-to > tol-1) return 0;
			/* Write the tail location (for clstate->tail) */
			if ((pblk-to) > (s-to)) {
				*tail = s;
				*sztail = (pblk-to) - (s-to);
			}
			else {
				*tail = NULL;
				*sztail = s-to;
			}
			/* strlrep gives exact new line length */
			return rh_strlrep(to, s-to, "\r\n", "\n");
		}

		/* Find LF */
		y = CSTR_SZ("\n\n");
		s = strstr(to, "\n\n");
		if (s) {
			if (!verify_ascii(to, s-to)) continue;
			*crlf = NO;
			s += y;
			if (s-to > tol-1) return 0;
			if ((pblk-to) > (s-to)) {
				*tail = s;
				*sztail = (pblk-to) - (s-to);
			}
			else {
				*tail = NULL;
				*sztail = s-to;
			}
			return s-to;
		}
	}

	return 0;
}

static size_t do_stream_file_reader(void *clstate, void *data, size_t szdata)
{
	struct client_state *uclstate = clstate;
	return io_read_data(uclstate->file_fd, data, szdata, YES, NULL);
}

static size_t do_stream_file_writer(void *clstate, const void *data, size_t szdata)
{
	struct client_state *uclstate = clstate;
	return io_send_data(uclstate->clinfo, data, szdata, YES, NO);
}

static rh_fsize do_stream_file_seeker(void *clstate, rh_fsize offset)
{
	struct client_state *uclstate = clstate;
	return (rh_fsize)lseek(uclstate->file_fd, (off_t)offset, SEEK_SET);
}

static void do_stream_file(struct client_state *clstate)
{
	struct io_stream_args ios_args;
	rh_yesno status;

	rh_memzero(&ios_args, sizeof(struct io_stream_args));

	ios_args.fn_args = clstate;
	ios_args.rdfn = do_stream_file_reader;
	ios_args.wrfn = do_stream_file_writer;
	ios_args.skfn = do_stream_file_seeker;

	ios_args.workbuf = clstate->workbuf;
	ios_args.wkbufsz = clstate->wkbufsz;

	ios_args.file_size = clstate->filesize;
	ios_args.start_from = clstate->range_start;
	ios_args.read_to = clstate->range_end;

	status = io_stream_file(&ios_args);

	clstate->iostate = ios_args.status;
	clstate->ioerror = ios_args.error;
	if (status == YES) {
		clstate->range_start = ios_args.start_from;
		clstate->range_end = ios_args.read_to;
	}
	clstate->sentbytes += ios_args.nr_written;
}

static char *client_header(const char *name)
{
	return find_header_value(clstate->headers, name);
}

static char *client_arg(const char *name)
{
	return find_arg_value(clstate->args, name);
}

static void tell_never_cache(struct client_state *clstate)
{
	time_t t = (time_t)679779600L;
	char *s;

	if (rh_no_cache_headers == YES) return;

	add_header(&clstate->sendheaders, "Cache-Control", "no-cache, no-store, must-revalidate");
	add_header(&clstate->sendheaders, "Pragma", "no-cache");
	s = getsdate(t, HTTP_DATE_FMT, YES);
	add_header(&clstate->sendheaders, "Expires", s);
	pfree(s);
}

static void tell_aggressive_cache(struct client_state *clstate)
{
	char *s;

	if (rh_no_cache_headers == YES) return;

	add_header(&clstate->sendheaders, "Cache-Control", "public, max-age=31536000");
	s = getsdate(clstate->request_time + 31536000L, HTTP_DATE_FMT, YES);
	add_header(&clstate->sendheaders, "Expires", s);
	pfree(s);
}

static void filter_special_htmlchars_sub(char **line, size_t sz, const char *chr, const char *schr)
{
_again:	if (rh_strlrep(*line, sz, chr, schr) >= sz) {
		if (sz < RH_ALLOC_SMALL) sz = RH_ALLOC_SMALL;
		sz /= 2; sz *= 3;
		if (sz >= RH_XSALLOC_MAX)
			xexits("failed to escape HTML characters!");
		*line = rh_realloc(*line, sz);
		goto _again;
	}
}

static void filter_special_htmlchars(char **line)
{
	size_t sz = rh_szalloc(*line);

	filter_special_htmlchars_sub(line, sz, "&", "&amp;");
	filter_special_htmlchars_sub(line, sz, "<", "&lt;");
	filter_special_htmlchars_sub(line, sz, ">", "&gt;");
	filter_special_htmlchars_sub(line, sz, "\"", "&quot;");
	filter_special_htmlchars_sub(line, sz, "'", "&#x27;");
	filter_special_htmlchars_sub(line, sz, "?", "&quest;");
	filter_special_htmlchars_sub(line, sz, "=", "&equals;");

	shrink_dynstr(line);
}

static const char *ppath(const char *ppath)
{
	return ppath ? ppath : "";
}

static void reset_client_state(struct client_state *clstate)
{
	size_t sz, x;

	clstate->request_time = (time_t)0L;
	pfree(clstate->request_date);

	pfree(clstate->tail);
	clstate->sztail = NOSIZE;
	sz = DYN_ARRAY_SZ(clstate->request_lines);
	for (x = 0; x < sz; x++) pfree(clstate->request_lines[x]);
	pfree(clstate->request_lines);
	clstate->is_crlf = NO;
	clstate->method = 0;
	pfree(clstate->request);
	pfree(clstate->protoversion);
	pfree(clstate->path);
	pfree(clstate->strargs);

	pfree(clstate->args);
	pfree(clstate->headers);

	pfree(clstate->realpath);
	clstate->filedir = 0;
	clstate->wants_dir = NO;
	if (clstate->file_fd != 0
	&& clstate->file_fd != -1) {
		close(clstate->file_fd);
		clstate->file_fd = -1;
	}
	clstate->is_exec = NO;
	clstate->is_rsrc = NO;
	clstate->is_indx = NO;
	clstate->cgi_mode = 0;
	clstate->workbuf = NULL;
	clstate->wkbufsz = 0;
	clstate->filesize = 0;
	clstate->range_start = 0;
	clstate->range_end = 0;
	clstate->recvbytes = 0;
	clstate->sentbytes = 0;
	clstate->iostate = 0;
	clstate->ioerror = 0;
	pfree(clstate->sendheaders);

	clstate->was_rewritten = NO;
	clstate->noindex = NO;
	if (clstate->hideindex_rgx) {
		regex_free(clstate->hideindex_rgx);
		clstate->hideindex_rgx = NULL;
	}
	pfree(clstate->prevpath);

	pfree(clstate->status);

	pfree(clstate->altlogline);

	pfree(clstate->prepend_path);
	if (rh_dir_prepend_path) clstate->prepend_path = rh_strdup(rh_dir_prepend_path);
}

static rh_yesno match_exec_pattern(const void *rgx, const char *root, const char *path)
{
	if (!strcmp(root, "/")) goto _ret;
	if (strncmp(path, root, strnlen(root, RH_XSALLOC_MAX)) != 0) return NO;
	path += strnlen(root, RH_XSALLOC_MAX);
_ret:	return regex_exec(rgx, path);
}

static void catch_status_code(struct client_state *clstate, const void *rdata, size_t rsz)
{
	char t[4];
	const char *s;
	size_t x;

	/* If already set, then do nothing! */
	if (clstate->status) return;

	s = rdata;
	/* should be at beginning - the very first line of CGI answer */
	if (!strncmp(s, "HTTP/", CSTR_SZ("HTTP/"))) {
		s += CSTR_SZ("HTTP/");
		x = strnlen(clstate->protoversion, RH_ALLOC_MAX);
		if (!strncmp(clstate->protoversion, s, x) && s[x] == ' ') {
			s += x+1;
			rh_strlcpy_real(t, s, sizeof(t));
			if (is_number(t, NO) == YES) clstate->status = rh_strdup(t);
		}
	}
}

static void force_timeout_exit(int sig)
{
	block_signals(YES, SIGALRM, 0);

	if (clstate->nr_requests == 0) {
		char *s = NULL;
		getdatetime(&s, rh_timefmt);
		rh_asprintf(&clstate->altlogline,
			"[%s]:%s [%s] %u no data received before timeout",
			clstate->ipaddr, clstate->clinfo->port, s, clstate->clinfo->pid);
		pfree(s);
		write_log_line(clstate);
	}

	rh_exit(0);
}

static void install_us_alarm(unsigned long long useconds)
{
	struct itimerval it;

	rh_memzero(&it, sizeof(struct itimerval));
	it.it_value.tv_sec = useconds / 1000000;
	it.it_value.tv_usec = useconds % 1000000;
	setitimer(ITIMER_REAL, &it, NULL);
}

static void set_timeout_alarm(unsigned long secs)
{
	install_us_alarm(0ULL);
	if (secs > 0) {
		signal(SIGALRM, force_timeout_exit);
		install_us_alarm(secs * 1000000ULL);
	}
	else signal(SIGALRM, SIG_IGN);
}

static void client_atexit(int status)
{
#ifdef WITH_TLS
	if (clstate->clinfo->cltls) {
		tls_close_notify(clstate->clinfo->cltls);
		TLS_send_pending(clstate->clinfo->clfd, clstate->clinfo->cltls);

		tls_destroy_context(clstate->clinfo->cltls);
		clstate->clinfo->cltls = NULL;

		if (clstate->clinfo->svtls) {
			tls_destroy_context(clstate->clinfo->svtls);
			clstate->clinfo->svtls = NULL;
		}
	}
#endif

	close(clstate->clinfo->clfd);
	if (clstate->clinfo->logfd != -1)
		close(clstate->clinfo->logfd);
}

static void signal_exit(int sig)
{
	block_signals(YES, sig, 0);

	if (sig == SIGTERM
	|| sig == SIGPIPE) { /* killed by CGI or improper pipe usage */
		if (!clstate->status) rh_asprintf(&clstate->status, "200");
		clstate->nr_requests++;
		write_log_line(clstate);
	}

	xexits("client: exited by signal %d", sig);
}

static void destroy_argv(char ***argv)
{
	size_t sz, x;
	char **uargv = *argv;

	sz = DYN_ARRAY_SZ(uargv);
	for (x = 0; x < sz; x++)
		pfree(*(uargv+x));
	rh_free(uargv); *argv = NULL;
}

struct dir_items {
	char *it_name; /* item file name */
	int it_type; /* PATH_IS_FILE or PATH_IS_DIR */
	rh_fsize it_size; /* item size */
	mode_t it_mode; /* item Unix chmod */
	uid_t it_owner; /* item Unix owner */
	gid_t it_group; /* item Unix group */
	time_t it_mtime; /* item modification time */
};

#define DI_SORTBY_NAME	1
#define DI_SORTBY_TYPE	2
#define DI_SORTBY_SIZE	3
#define DI_SORTBY_OWNER	4
#define DI_SORTBY_GROUP	5
#define DI_SORTBY_MTIME	6

static int di_sortby = DI_SORTBY_NAME;
static rh_yesno di_reverse_sort;

static int dir_sort_compare(const void *pdi1, const void *pdi2)
{
	const struct dir_items *di1 = pdi1;
	const struct dir_items *di2 = pdi2;

	if (di_reverse_sort == YES) {
		di1 = pdi2;
		di2 = pdi1;
	}

	if (di_sortby == DI_SORTBY_NAME) {
_fallback:	return strcmp(di1->it_name, di2->it_name);
	}
	else if (di_sortby == DI_SORTBY_TYPE) {
		if (di1->it_type == PATH_IS_DIR && di2->it_type != PATH_IS_DIR) return -1;
		else if (di1->it_type == di2->it_type) goto _fallback;
		else return 1;
	}
	else if (di_sortby == DI_SORTBY_SIZE) {
		if (di1->it_size > di2->it_size) return -1;
		else if (di1->it_size == di2->it_size) goto _fallback;
		else return 1;
	}
	else if (di_sortby == DI_SORTBY_OWNER) {
		if (di1->it_owner < di2->it_owner) return -1;
		else if (di1->it_owner == di2->it_owner) goto _fallback;
		else return 1;
	}
	else if (di_sortby == DI_SORTBY_GROUP) {
		if (di1->it_group < di2->it_group) return -1;
		else if (di1->it_group == di2->it_group) goto _fallback;
		else return 1;
	}
	else if (di_sortby == DI_SORTBY_MTIME) {
		if (di1->it_mtime > di2->it_mtime) return -1;
		else if (di1->it_mtime == di2->it_mtime) goto _fallback;
		else return 1;
	}

	return 0;
}

static void free_dir_items(struct dir_items *di)
{
	size_t sz, x;

	sz = DYN_ARRAY_SZ(di);
	if (sz == 0) return;

	for (x = 0; x < sz; x++) pfree(di[x].it_name);
	pfree(di);
}

static char *rh_which(const char *envpath, const char *name)
{
	char *T, *s, *d, *t;
	char *r;
	rh_yesno x;

	T = rh_strdup(envpath);
	s = d = T; t = r = NULL; x = NO;
	while ((s = strtok_r(d, ":", &t))) {
		if (d) d = NULL;

		rh_asprintf(&r, "%s/%s", s, name);
		if (is_exec(r)) {
			x = YES;
			break;
		}
	}

	pfree(T);

	if (x == YES) {
		shrink_dynstr(&r);
		return r;
	}

	pfree(r);
	return NULL;
}

#define cgisetenv(to, fmt, ss, dd)								\
	do {											\
		size_t sz;									\
		rh_asprintf(&to, fmt, ss, dd);							\
		sz = DYN_ARRAY_SZ(tenvp);							\
		tenvp = rh_realloc(tenvp, (sz+(sz == 0 ? 2 : 1)) * sizeof(char *));		\
		if (sz) sz--;									\
		*(tenvp+sz) = rh_strdup(to);							\
	} while (0)

void run_client(struct client_info *clinfo)
{
	size_t x, sz;
	char *s, *d, *t;
	const struct embedded_resource *rsrc;
	struct embedded_resource *drsrc;
	int err;

	/* install client default signals */
	for (err = 1; err < NSIG; err++) {
		if (err == SIGPIPE
		|| err == SIGCONT
		|| err == SIGHUP) signal(err, SIG_IGN);
		else signal(err, signal_exit);
	}

	/* obtain io pool */
	client_read_pool = rh_malloc(rh_rdwr_bufsize);

	/* obtain new client request */
	clstate = rh_malloc(sizeof(struct client_state));
	reset_client_state(clstate);
	clstate->clinfo = clinfo;
	clstate->ipaddr = clinfo->ipaddr;
	clstate->httproot = rh_strdup(rh_root_dir);

	/* First time handler for read from client: if client is lazy, the timeout will drop him. */
	set_timeout_alarm(rh_client_request_timeout);

	/* Secure destroy. */
	rh_atexit = client_atexit;

#ifdef WITH_TLS
	/* TLS stuff. */
	if (clinfo->cltls == THIS_IS_TLS_CONN) {
		/* Create new client TLS context */
		clinfo->cltls = tls_accept(clinfo->svtls);
		if (!clinfo->cltls)
			xexits("Creating TLS client context failed");
		/* Parse initial client hello & stuff */
		while (tls_established(clinfo->cltls) <= 0) {
			if (TLS_parsemsg(clinfo->cltls, clinfo->clfd,
			client_read_pool, rh_rdwr_bufsize) == NO) {
				set_timeout_alarm(0);
				if (clstate->nr_requests == 0) {
					s = NULL;
					getdatetime(&s, rh_timefmt);
					rh_asprintf(&clstate->altlogline,
						"[%s]:%s [%s] %u TLS message corrupted or error",
						clstate->ipaddr, clinfo->port, s, clinfo->pid);
					pfree(s);
					write_log_line(clstate);
				}
				goto _do_exit;
			}
		}
	}
#endif

_start:	s = d = t = NULL;
	/* read raw request from client up to maximum buffer size */
	x = read_raw_request(
		clinfo, client_read_pool, rh_rdwr_bufsize,
		&clstate->is_crlf, &s, &sz);
	if (x == 0 || x == NOSIZE) { /* do not answer anything if request is empty or errored */
		/* Do not interrupt in the middle of allocation!! */
		set_timeout_alarm(0);
		/* Single session must be logged, even if empty. Keep-alived however not. */
		if (clstate->nr_requests == 0) {
			s = NULL;
			getdatetime(&s, rh_timefmt);
			rh_asprintf(&clstate->altlogline,
				"[%s]:%s [%s] %u empty, malformed or error request",
				clstate->ipaddr, clinfo->port, s, clinfo->pid);
			pfree(s);
			write_log_line(clstate);
		}
		goto _do_exit;
	}

	/* processing starts - disable keep alive timeout signal! */
	clstate->request_time = getdatetime(&clstate->request_date, rh_timefmt);
	set_timeout_alarm(0);

	/* Save a tail if there is a data on it. Useful for CGI POST. */
	if (s) {
		if (!memtest(s, sz, 0)) {
			clstate->tail = rh_memdup(s, sz);
			clstate->sztail = sz;
			clstate->recvbytes += sz;
		}
	}
	else {
		if (!memtest(client_read_pool+sz, rh_rdwr_bufsize-1-sz, 0)) {
			clstate->tail = rh_memdup(client_read_pool+sz, rh_rdwr_bufsize-1-sz);
			clstate->sztail = NOSIZE;
		}
	}

	/* split into separate lines */
	s = d = client_read_pool; t = NULL;
	while ((s = strtok_r(d, "\n", &t))) { /* parse by Unix line endings */
		if (d) d = NULL;

		/* Request ended. Drop any garbage beyond. */
		if (str_empty(s)) break;

		/* Size indicator. If 0, then apply different line length rules to request line */
		sz = DYN_ARRAY_SZ(clstate->request_lines);

		/* Check line length */
		if (sz == 0) {
			if (strnlen(s, RH_ALLOC_MAX) >= HTTP_REQUEST_MAX) goto _malformed;
			/* Filter line off the fmtstr templates */
			nuke_fmtstr_templates(s, strnlen(s, HTTP_REQUEST_MAX)+1);
		}
		else {
			if (strnlen(s, RH_ALLOC_MAX) >= HTTP_REQHEAD_MAX) goto _malformed;
			/* Filter line off the fmtstr templates */
			nuke_fmtstr_templates(s, strnlen(s, HTTP_REQHEAD_MAX)+1);
		}

		/* Add line */
		clstate->request_lines = rh_realloc(clstate->request_lines,
			(sz+1) * sizeof(char *));
		clstate->request_lines[sz] = rh_strdup(s);
	}

	/* For some reason, there even were no any request lines. Just drop such client. */
	if (!clstate->request_lines) {
_malformed:
		s = NULL;
		getdatetime(&s, rh_timefmt);
		rh_asprintf(&clstate->altlogline,
			"[%s]:%s [%s] %u malformed request lines, rejecting",
			clstate->ipaddr, clinfo->port, s, clinfo->pid);
		pfree(s);
		write_log_line(clstate);
		goto _do_exit;
	}

	/* request_lines[0] is request method. Parse it now. */
	s = t = rh_strdup(clstate->request_lines[0]);

	d = strchr(s, ' ');
	if (!d) {
		response_error(clstate, 400); /* nonsense from client */
		goto _done;
	}
	*d = 0; d++;
	if (!strcmp(s, "GET")) {
		clstate->method = REQ_METHOD_GET;
	}
	else if (!strcmp(s, "HEAD")) {
		clstate->method = REQ_METHOD_HEAD;
	}
	else if (!strcmp(s, "POST")) {
		clstate->method = REQ_METHOD_POST;
	}
	else {
		response_error(clstate, 400);
		goto _done;
	}

	/* decode path and protocol version */
	s = rh_strdup(d);
	/* parse protoversion */
	d = strstr(s, "HTTP/");
	if (!d) {
		clstate->protoversion = rh_strdup("0.9"); /* simply "GET /path", this is 0.9. */
	}
	else {
		if (d-s < 2) { /* at least needs to be "/ HTTP/1.0" */
			response_error(clstate, 400);
			goto _done;
		}

		d += CSTR_SZ("HTTP/");
		if (!strcmp(d, "0.9")
		|| !strcmp(d, "1.0")
		|| !strcmp(d, "1.1")) {
			clstate->protoversion = rh_strdup(d); /* for response */
		}
		else { /* you have bad request */
			response_error(clstate, 400);
			goto _done;
		}
		/* ok, version saved, need to obtain path */
		d -= CSTR_SZ("HTTP/")+1;
		if (*d != ' ') { /* malformed */
			response_error(clstate, 400);
			goto _done;
		}
		*d = 0; /* s now is the unparsed path */
	}

	/* save full request line (with params) */
	clstate->request = rh_strdup(s);
	/* decode url */
	urldecode(clstate->request, rh_szalloc(clstate->request));
	/* filter off fmtstr templates, if any */
	nuke_fmtstr_templates(clstate->request, rh_szalloc(clstate->request));
	/* same memory space */
	shrink_dynstr(&clstate->request);

	/* done with temporary. */
	pfree(s);

	/* client may pass some parameters. Split the path into two if there's any. */
	s = rh_strdup(clstate->request);
	d = strchr(s, '?');
	if (d) {
		*d = 0;
		d++;
	}
	clstate->path = rh_strdup(s);
	if (d) {
		clstate->strargs = rh_strdup(d);
		rh_strlrep(clstate->strargs, rh_szalloc(clstate->strargs), "+", " ");
	}
	pfree(s);

	/* done with request method line. */
	pfree(t);

	/* do security filtering */
	x = strnlen(clstate->path, RH_XSALLOC_MAX);
	if (x > 0 && clstate->path[x-1] == '/') clstate->wants_dir = YES;
	x = filter_dotdots(clstate->path, rh_szalloc(clstate->path));
	if (clstate->strargs) {
		filter_dotdots(clstate->strargs, rh_szalloc(clstate->strargs));
		clstate->args = parse_args(clstate->strargs);
	}

	/* If result if filtering was devastative, then someone is misbehaving. */
	if (x == 0 || str_empty(clstate->path)) {
		response_error(clstate, 400);
		goto _done;
	}

	/*
	 * If there was a bizarre request and first character
	 * of path is not '/', then 400 for you. Go away.
	 */
	if (clstate->path[0] != '/') {
		response_error(clstate, 400);
		goto _done;
	}

	/* just save client headers, header query system will reuse them. */
	clstate->headers = parse_headers(clstate->request_lines, 1, 0);

	/* Set xrealip condition */
	if (rh_xrealip && !strcmp(clstate->ipaddr, rh_xrealip))
		clstate->xrealip_authed = YES;
	else clstate->xrealip_authed = NO;

	/* Lookup X-Real-IP header if there is a need */
	if (clstate->xrealip_authed == YES) {
		s = client_header("X-Real-IP");
		if (s) clstate->ipaddr = rh_strdup(s);
	}
	/*
	 * Lookup X-Base-Path header if frontend serves multiple directories to us.
	 * NOTE: -O xrealip= must be set. If frontend does not give us xrealip, then
	 * client address will not be overwritten. And do you trust your frontend?
	 */
	if (clstate->xrealip_authed == YES) {
		s = client_header("X-Base-Path");
		if (s) {
			pfree(clstate->prepend_path);
			clstate->prepend_path = rh_strdup(s);
		}
	}

	/*
	 * If there was a tail, then it's POST definitely.
	 * Let's find out it's real length, and if there is
	 * no any - then drop it to save memory space.
	 */
	if (clstate->tail) {
		s = client_header("Content-Length");
		if (s) {
			if (clstate->sztail == NOSIZE) {
				char *stoi;

				x = rh_str_size(s, &stoi);
				if (!str_empty(stoi)) {
					response_error(clstate, 400);
					goto _done;
				}

				sz = rh_szalloc(clstate->tail);
				if (x > sz) x = sz;
				clstate->tail = rh_realloc(clstate->tail, x);
				clstate->recvbytes += x;
			}
		}
		else pfree(clstate->tail); /* not so useful, drop it */
	}

	/* admin disabled keepalive - skip it */
	if (rh_client_keepalive_timeout == 0) goto _disabledkeepalive;

	/* No no, old protocol just has no that. */
	if (!strcmp(clstate->protoversion, "0.9")) {
_disabledkeepalive:
		clstate->is_keepalive = NO;
		delete_header(&clstate->sendheaders, "Keep-Alive");
		goto _skipkeepalive;
	}

	/* find out if client requested keep alive */
	s = client_header("Connection");
	if (!s) {
		if (!strcmp(clstate->protoversion, "1.1")) {
			/* Assume keep-alive by default for 1.1 version */
			clstate->is_keepalive = YES;
		}
		else {
			clstate->is_keepalive = NO; /* default to single session */
			delete_header(&clstate->sendheaders, "Keep-Alive");
		}
	}
	else {
		if (!strcasecmp(s, "keep-alive")) { /* wants keepalive */
			clstate->is_keepalive = YES;
		}
		else if (!strcasecmp(s, "close")) { /* decided to terminate this connection */
			clstate->is_keepalive = NO;
			delete_header(&clstate->sendheaders, "Keep-Alive");
		}
	}

	if (clstate->is_keepalive) {
		/* Notify client about our keep alive policy */
		s = NULL;
		rh_asprintf(&s, "timeout=%lu, max=%zu",
			rh_client_keepalive_timeout, rh_client_keepalive_requests);
		add_header(&clstate->sendheaders, "Keep-Alive", s);
		pfree(s);
	}

_skipkeepalive:
_hta_rewrite:
	/* ### response phase ### */

	/* Find and send resource. See resource.c for comments. */
	rsrc = find_resource_args(clstate->path, clstate->strargs);
	if (rsrc) {
_defres:	if (clstate->method > REQ_METHOD_HEAD) {
			add_header(&clstate->sendheaders, "Allow", "GET, HEAD");
			response_error(clstate, 405);
			goto _done;
		}

		/* currently not serving "directory" resources. */
		if (clstate->wants_dir == YES) {
			response_error(clstate, 400);
			goto _done;
		}

		if (clstate->prepend_path && rsrc->is_static == NO) {
			drsrc = clone_resource(rsrc);
			if (resource_prepend_path(drsrc, clstate->prepend_path) == NO)
				free_resource(drsrc);
			else rsrc = drsrc;
		}
		else drsrc = NULL;

		pfree(clstate->realpath);
		if (rsrc->path)
			rh_astrcat(&clstate->realpath, rsrc->path);
		else /* secret resource should have at least "name" set. */
			rh_astrcat(&clstate->realpath, rsrc->name);
		clstate->filedir = PATH_IS_FILE;
		clstate->is_rsrc = YES; /* yes, resource. Do not try to read from fd. */
		clstate->filesize = (rh_fsize)rsrc->szdata;

		/* Add resource Last-Modified header */
		s = getsdate(rsrc->lastmod, HTTP_DATE_FMT, YES);
		add_header(&clstate->sendheaders, "Last-Modified", s);
		pfree(s);

		s = NULL;
		rh_asprintf(&s, "%zu", rsrc->szdata);
		add_header(&clstate->sendheaders, "Content-Length", s);
		pfree(s);
		add_header(&clstate->sendheaders, "Content-Type", rsrc->mimetype);
		/* Always cache static content */
		tell_aggressive_cache(clstate);

		response_ok(clstate, 200, YES);
		response_send_data(clstate, rsrc->data, rsrc->szdata);

		if (drsrc) free_resource(drsrc);
		goto _done;
	}

	/* Check if given Host: is matching the http server name */
	if (rh_hostnames_rgx) {
		s = client_header("Host");
		if (!s) {
_badhost:		response_error(clstate, 404);
			goto _done;
		}
		else if (s && regex_exec(rh_hostnames_rgx, s) == NO) goto _badhost;
	}

	/* Setup response */
	rh_memzero(client_read_pool, rh_szalloc(client_read_pool));
	clstate->workbuf = client_read_pool;
	clstate->wkbufsz = rh_szalloc(client_read_pool);

	/* Are we serving single executable? */
	if (rh_cgiserver) {
		clstate->realpath = rh_strdup(rh_cgiserver);
		clstate->filedir = PATH_IS_FILE; /* is_exec will check it's presence */
		clstate->cgi_mode = rh_cgi_mode;
		goto _cgiserver;
	}

	/* Pretranslate: determine if it even exists */
	d = NULL;
	rh_astrcat(&d, clstate->httproot);
	rh_astrcat(&d, "/");
	rh_astrcat(&d, clstate->path);
	rh_strlrep(d, rh_szalloc(d), "//", "/");
	if (rh_follow_symlinks == YES) s = rh_strdup(d);
	else s = rh_realpath(d);
	if (!s) {
_not_found:
		/* If no robots.txt here, provide an embedded one */
		if (!strcmp(clstate->path, "/robots.txt")) {
			rsrc = find_resource(RESTYPE_NAME, "robots.txt");
			if (rsrc) goto _defres;
		}

		/* If no favicon here, provide an embedded one */
		if (!strcmp(clstate->path, "/favicon.ico")) {
			rsrc = find_resource(RESTYPE_NAME, "favicon.ico");
			if (rsrc) goto _defres;
		}

		/*
		 * Ok let's try traverse into possible parent directory
		 * to see htaccess file permissions
		 */
		s = dirname(d);
		if (strncmp(s, clstate->httproot, strnlen(clstate->httproot, RH_XSALLOC_MAX)) != 0) {
			/* Bad. */
			pfree(d);
			response_error(clstate, 403);
			goto _done;
		}

		/* Good, let's try htaccess */
		err = verify_htaccess(clstate, s, clstate->httproot);
		pfree(d);
		if (err == HTA_REWRITE) goto _hta_rewrite;
		if (err) {
			/* Yea! */
			response_error(clstate, err);
			goto _done;
		}

		/* nothing matched: return a real 404 error. */
		response_error(clstate, 404);
		goto _done;
	}
	pfree(d);
	if (strncmp(s, clstate->httproot, strnlen(clstate->httproot, RH_XSALLOC_MAX)) != 0) {
		response_error(clstate, 403); /* yes, stepping outside of root directory */
		goto _done;
	}
	clstate->realpath = s;
	rh_strlrep(clstate->realpath, rh_szalloc(clstate->realpath), "//", "/");

	clstate->filedir = file_or_dir(clstate->realpath);
	/*
	 * error not catched by realpath previously, or symlink
	 * following mode, in which real path is not checked.
	 */
	if (clstate->filedir == -1) {
		if (errno == ENOENT) {
			d = clstate->realpath;
			clstate->realpath = NULL;
			goto _not_found;
		}
		else response_error(clstate, rh_on_fs_error ? rh_on_fs_error : 403);
		goto _done;
	}
	/* direct file */
	else if (clstate->filedir == PATH_IS_FILE) {
		/*
		 * Verify the user has access.
		 *
		 * .htaccess rules may return other error code
		 * for the is_htaccess test below. For example,
		 * completely hide .htaccess files with rewrite.
		 */
		err = verify_htaccess(clstate, clstate->realpath, clstate->httproot);
		if (err == HTA_REWRITE) goto _hta_rewrite;
		if (err > 0) {
			response_error(clstate, err);
			goto _done;
		}

		/* Verify user not requesting htaccess control file */
		if (is_htaccess(clstate->realpath)) {
			response_error(clstate, 403);
			goto _done;
		}

		/* user wanted directory but this is not a directory - fail. */
		if (clstate->wants_dir == YES) {
			response_error(clstate, 400);
			goto _done;
		}

_sendidx:	/* Find out if it is potential CGI executable */
		if (match_exec_pattern(rh_cgiexecs_rgx, clstate->httproot, clstate->realpath))
			clstate->cgi_mode = CGI_MODE_REGULAR;
		else if (match_exec_pattern(rh_nhcgiexecs_rgx, clstate->httproot, clstate->realpath))
			clstate->cgi_mode = CGI_MODE_NOHEADS;
		else if (match_exec_pattern(rh_cgiehexecs_rgx, clstate->httproot, clstate->realpath))
			clstate->cgi_mode = CGI_MODE_ENDHEAD;

		/* File is executable - execute it, forward output to client. */
		if (clstate->cgi_mode > 0) {
			char *targv[3], **tenvp;
			char *wdir;
			int fpfd[2], tpfd[2], epfd[2], err;
			struct pollfd polldf[2];
			pid_t pid;

_cgiserver:		tenvp = NULL;
			err = NO;

			/* Do not expose potential CGI file contents */
			if (rh_try_shell_exec == NO && !is_exec(clstate->realpath)) {
				response_error(clstate, 403);
				goto _done;
			}

			/* Mark as executed CGI script */
			clstate->is_exec = YES;

			/* I was told that most http servers do this. */
			wdir = rh_strdup(clstate->realpath);
			d = strrchr(wdir, '/');
			if (d) *d = 0;
			chdir(wdir);

			/* set CGI envvars */
			t = client_read_pool;

			switch (clstate->cgi_mode) {
				case CGI_MODE_REGULAR: d = "regular"; break;
				case CGI_MODE_NOHEADS: d = "noheaders"; break;
				case CGI_MODE_ENDHEAD: d = "noendhead"; break;
				default: d = ""; break;
			}
			cgisetenv(t, "%s=%s", "CGI_MODE", d);

			cgisetenv(t, "%s=%u", "SERVER_PID", clinfo->pid);
			cgisetenv(t, "%s=%s", "PATH", rh_cgi_path);
			cgisetenv(t, "%s=%s", "SERVER_SOFTWARE", rh_ident);
			cgisetenv(t, "%s=%s", "GATEWAY_INTERFACE", "CGI/1.1");

			if (rh_hostnames) d = rh_strdup(rh_hostnames);
			else d = getmyhostname();
			cgisetenv(t, "%s=%s", "SERVER_NAME", d ? d : "");
			pfree(d);

			cgisetenv(t, "%s=%s", "REMOTE_ADDR", clstate->ipaddr);
			cgisetenv(t, "%s=%s", "REMOTE_HOST", clstate->ipaddr);

			d = NULL;
			rh_asprintf(&d, "HTTP/%s", clstate->protoversion);
			cgisetenv(t, "%s=%s", "SERVER_PROTOCOL", d);
			pfree(d);

			cgisetenv(t, "%s=%s", "SERVER_PORT", clinfo->servport);
#ifdef WITH_TLS
			if (rh_tlsport_s) cgisetenv(t, "%s=%s", "SERVER_TLS_PORT", rh_tlsport_s);
#endif
			cgisetenv(t, "%s=%s", "REMOTE_PORT", clinfo->port);

			cgisetenv(t, "%s=%s", "PWD", wdir);

			d = urlencode(clstate->strargs);
			cgisetenv(t, "%s=%s", "QUERY_STRING", d);
			pfree(d);

			cgisetenv(t, "%s=%s", "REQUEST_DATE", clstate->request_date);

			d = getsdate(clstate->request_time, "%s", NO);
			cgisetenv(t, "%s=%s", "REQUEST_TIMESTAMP", d);
			pfree(d);

			cgisetenv(t, "%s=%s", "REQUEST_LINE", clstate->request_lines[0]);

			switch (clstate->method) {
				case REQ_METHOD_GET: d = "GET"; break;
				case REQ_METHOD_HEAD: d = "HEAD"; break;
				case REQ_METHOD_POST: d = "POST"; break;
				default: d = "?"; break;
			}
			cgisetenv(t, "%s=%s", "REQUEST_METHOD", d);

			cgisetenv(t, "%s=%s", "PATH_INFO", clstate->path);
			cgisetenv(t, "%s=%s", "SCRIPT_NAME", clstate->path);
			cgisetenv(t, "%s=%s", "PATH_TRANSLATED", clstate->realpath);
			cgisetenv(t, "%s=%s", "CLIENT_LINE_ENDINGS",
				clstate->is_crlf == YES ? "CRLF" : "LF");

			if (clstate->prepend_path)
				cgisetenv(t, "%s=%s", "SERVER_PREPEND_PATH", clstate->prepend_path);

			cgisetenv(t, "%s=%s", "SERVER_ROOT", clstate->httproot);
			if (rh_chroot_dir) cgisetenv(t, "%s=%s", "SERVER_CHROOT", rh_chroot_dir);
			switch (clinfo->af) {
				case AF_INET: d = "IPv4"; break;
				case AF_INET6: d = "IPv6"; break;
				default: d = ""; break;
			}
			cgisetenv(t, "%s=%s", "CLIENT_ADDR_FAMILY", d);
			cgisetenv(t, "%s=%s", "CLIENT_ADDR", clinfo->ipaddr);
#ifdef WITH_TLS
			cgisetenv(t, "%s=%s", "CLIENT_PROTOCOL", clinfo->cltls ? "https" : "http");
#else
			cgisetenv(t, "%s=%s", "CLIENT_PROTOCOL", "http");
#endif
			cgisetenv(t, "%s=%u", "CLIENT_KEEP_ALIVE", clstate->is_keepalive == YES ? 1 : 0);
			cgisetenv(t, "%s=%u", "REQUEST_NUMBER", clstate->nr_requests);

			s = client_header("Host");
			if (s) cgisetenv(t, "%s=%s", "HTTP_HOST", s);
			s = client_header("Referer");
			if (s) cgisetenv(t, "%s=%s", "HTTP_REFERER", s);
			s = client_header("User-Agent");
			if (s) cgisetenv(t, "%s=%s", "HTTP_USER_AGENT", s);
			s = client_header("Cookie");
			if (s) cgisetenv(t, "%s=%s", "HTTP_COOKIE", s);
			s = client_header("Range");
			if (s) cgisetenv(t, "%s=%s", "CONTENT_RANGE", s);
			s = client_header("Content-Type");
			if (s) cgisetenv(t, "%s=%s", "CONTENT_TYPE", s);
			s = client_header("Content-Length");
			if (s) cgisetenv(t, "%s=%s", "CONTENT_LENGTH", s);

			rh_memzero(client_read_pool, rh_szalloc(client_read_pool));

			s = rh_strdup(clstate->realpath);
			targv[0] = rh_strdup(basename(s));
			pfree(s);
			if (clstate->is_indx == YES)
				targv[1] = rh_strdup(wdir);
			else if (rh_cgiserver) targv[1] = rh_strdup(clstate->path);
			else targv[1] = NULL;
			targv[2] = NULL;

			pfree(wdir);

			/* From CGI: WX(CGI), RX(US) */
			if (pipe(fpfd) != 0) {
				response_error(clstate, 500);
				goto _done;
			}

			/* To CGI: WX(US), RX(CGI) */
			if (pipe(tpfd) != 0) {
				response_error(clstate, 500);
				goto _done;
			}

			/* Error handling pipe */
			if (pipe(epfd) != 0) {
				response_error(clstate, 500);
				goto _done;
			}

			fcntl(epfd[0], F_SETFD, fcntl(epfd[0], F_GETFD) | FD_CLOEXEC);
			fcntl(epfd[1], F_SETFD, fcntl(epfd[1], F_GETFD) | FD_CLOEXEC);

			pid = fork();
			switch (pid) {
				case -1:
					close(epfd[0]);
					close(epfd[1]);
					close(fpfd[0]);
					close(fpfd[1]);
					close(tpfd[0]);
					close(tpfd[1]);
					err = YES;
					goto _out;
					break;
				case 0:
					close(clinfo->clfd);
					close(epfd[0]);
					for (x = 1; x < NSIG; x++) signal(x, SIG_DFL);
					clear_environ();
					close(fpfd[0]);
					close(tpfd[1]);
					close(0);
					if (dup2(tpfd[0], 0) == -1) goto _xclerr;
					close(1);
					if (dup2(fpfd[1], 1) == -1) goto _xclerr;
					close(2);
					if (dup2(fpfd[1], 2) == -1) goto _xclerr;
					close(fpfd[1]);
					close(tpfd[0]);
					err = execve(clstate->realpath, targv, tenvp);
					if (err == -1) {
						char *sh;

						if (rh_try_shell_exec == NO) goto _xclerr;

						sh = rh_which(rh_cgi_path, "sh");
						if (!sh) {
							errno = ENOENT;
							goto _xclerr;
						}
						err = execle(sh, "sh", clstate->realpath, NULL, tenvp);
_xclerr:					write(epfd[1], &errno, sizeof(errno));
					}
					close(epfd[1]);
					rh_exit(127);
					break;
				default:
					close(epfd[1]);
					signal(SIGCHLD, SIG_DFL);
					err = 0;
					while (read(epfd[0], &err, sizeof(errno)) != -1)
						if (errno != EAGAIN && errno != EINTR) break;
					close(epfd[0]);
					if (err) {
						close(fpfd[0]);
						close(fpfd[1]);
						close(tpfd[0]);
						close(tpfd[1]);
						err = YES;
						goto _out;
					}
					err = -1;
					close(fpfd[1]);
					close(tpfd[0]);

					if (clstate->tail) {
						rh_memzero(polldf, sizeof(polldf));
						polldf[0].fd = tpfd[1];
						polldf[0].events = POLLOUT;

_pollagain:					if (poll(polldf, 1, -1) == -1) {
							if (errno == EINTR) goto _pollagain;
							err = YES;
							goto _out;
						}

						if (polldf[0].revents) {
							errno = 0;
							x = rh_szalloc(clstate->tail);
							io_write_data(tpfd[1], clstate->tail, x, NO, NULL);
						}
					}

					if (clstate->cgi_mode == CGI_MODE_REGULAR
					|| clstate->cgi_mode == CGI_MODE_ENDHEAD) {
						/*
						 * well even if supported, you should activate header
						 * generation offload or header appending and update
						 * your CGI exec to do that.
						 */
						if (clstate->cgi_mode == CGI_MODE_REGULAR) {
							add_header(&clstate->sendheaders, "Accept-Ranges", "none");
							add_header(&clstate->sendheaders, "Content-Type", "text/html");
							/* Tell to never cache. */
							tell_never_cache(clstate);
						}
						/*
						 * Sorry, I do not know how much content will be
						 * written to you. Forcing Connection: close.
						 * Note that CGI script acting as HTTP server
						 * may do what it want with headers, including
						 * leaving keep-alive state unchanged.
						 */
						clstate->is_keepalive = NO;
						delete_header(&clstate->sendheaders, "Keep-Alive");
						response_ok(clstate, 200,
							(clstate->cgi_mode == CGI_MODE_REGULAR) ? YES : NO);
					}

					rh_memzero(polldf, sizeof(polldf));
					polldf[0].fd = clinfo->clfd;
					polldf[0].events = POLLIN;
					polldf[1].fd = fpfd[0];
					polldf[1].events = POLLIN;
					while (1) {
						if (poll(polldf, 2, -1) == -1) {
							if (errno == EINTR) continue;
							break;
						}

						if (polldf[0].revents) {
							errno = 0;
							if (polldf[0].revents == POLLHUP) break;
							x = response_recv_data(clstate,
							clstate->workbuf, clstate->wkbufsz);
							if (x == 0 || x == NOSIZE) break;
							io_write_data(tpfd[1], clstate->workbuf, x, NO, NULL);
						}
						if (polldf[1].revents) {
							errno = 0;
							if (polldf[1].revents == POLLHUP) break;
							x = io_read_data(fpfd[0],
							clstate->workbuf, clstate->wkbufsz, YES, NULL);
							if (x == 0 || x == NOSIZE) break;
							if (clstate->cgi_mode == CGI_MODE_NOHEADS) {
								catch_status_code(clstate,
								clstate->workbuf, x);
							}
							response_send_data(clstate,
							clstate->workbuf, x);
						}
					}
					close(fpfd[0]);
					close(tpfd[1]);
					waitpid(pid, NULL, 0);
					signal(SIGCHLD, signal_exit);
					err = NO;
					break;
			}

_out:			destroy_argv(&tenvp);
			pfree(targv[0]);
			pfree(targv[1]);

			if (err == YES) {
				response_error(clstate, 500);
				goto _done;
			}
			else {
				/* Mark as successive. */
				if (!clstate->status)
					rh_asprintf(&clstate->status, "200");
			}

			/* done. */
			goto _done;
		}
		/* send plain file or it's part */
		else {
			struct stat stst;

			/* POST is not permitted for plain files */
			if (clstate->method > REQ_METHOD_HEAD) {
				add_header(&clstate->sendheaders, "Allow", "GET, HEAD");
				response_error(clstate, 405);
				goto _done;
			}

#ifdef O_LARGEFILE
			clstate->file_fd = open(clstate->realpath, O_RDONLY | O_LARGEFILE);
#else
			clstate->file_fd = open(clstate->realpath, O_RDONLY);
#endif
			if (clstate->file_fd == -1) { /* not permitted for some reason */
				response_error(clstate, 403);
				goto _done;
			}

			if (fstat(clstate->file_fd, &stst) == -1) {
				response_error(clstate, 403);
				goto _done;
			}

			clstate->filesize = rh_fdsize(clstate->file_fd);
			if (clstate->filesize == NOFSIZE) {
				/*
				 * last chance to obtain real size for
				 * small files like /proc/uptime.
				 * 32k here should be enough.
				 */
				clstate->filesize = (rh_fsize)pread(clstate->file_fd,
					clstate->workbuf, clstate->wkbufsz, 0);
				if (clstate->filesize == NOFSIZE) {
					/* do not specify reason, it just failed!! */
					response_error(clstate, 403);
					goto _done;
				}
			}
			if (clstate->filesize == 0 && S_ISCHR(stst.st_mode))
				clstate->filesize = (rh_fsize)0xffffffffffffULL; /* 256T enough? */

			/* Never cache the sent file */
			tell_never_cache(clstate);

			/* Add Last-Modified header */
			s = getsdate(stst.st_mtime, HTTP_DATE_FMT, YES);
			add_header(&clstate->sendheaders, "Last-Modified", s);
			pfree(s);

#ifdef WITH_LIBMAGIC
			s = get_mime_fd(clstate->file_fd, clstate->workbuf, clstate->wkbufsz);
#else
			s = get_mime_filename(clstate->realpath);
#endif
			add_header(&clstate->sendheaders, "Content-Type",
				s ? s : "application/octet-stream; charset=binary");
			pfree(s);

			/* User requests explicit download box */
			s = client_arg("dl");
			if (s && !(!strcmp(s, "0"))) {
				d = rh_strdup(clstate->realpath);
				t = rh_strdup(basename(d));
				rh_asprintf(&d, "attachment; filename=\"%s\"", t);
				add_header(&clstate->sendheaders, "Content-Disposition", d);
				pfree(d);
				pfree(t);
			}

			/* User wants to view it in browser */
			s = client_arg("vi");
			if (s && !(!strcmp(s, "0"))) {
				add_header(&clstate->sendheaders, "Content-Disposition", "inline");
				/*
				 * Ohh, if there is a binary like mime type, then
				 * let's crudely make client believe it's a viewable thing.
				 * Do not touch others (such as images, docs, audio and video),
				 * since they're maybe interpreted by any modern browser.
				 */
				s = find_header_value(clstate->sendheaders, "Content-Type");
				if (s) {
					if (strstr(s, "application/"))
						add_header(&clstate->sendheaders,
						"Content-Type", "text/plain");
				}
			}

			/* Notify that we accept only byte ranges */
			add_header(&clstate->sendheaders, "Accept-Ranges", "bytes");
			/* Range parsing code */
			s = client_header("Range");
			if (!s) {
				s = client_arg("range"); /* maybe "?range=" was passed? */
				if (s && !str_empty(s)) goto _rangeparser;
			}
			if (s && !str_empty(s)) {
				char *stoi;

				/*
				 * Ranges other than bytes are NOT supported.
				 * Multipart ranges are NOT supported.
				 * Sorry, I am too lazy to implement multiparts.
				 * If you expect them to be present here, please
				 * ask me to do so. We'll figure it out.
				 * This Range code is made only to satisfy a single
				 * part of file to be transferred.
				 */
				if ((!(!strncasecmp(s, "bytes=", CSTR_SZ("bytes="))))
				|| (strchr(s, ','))) {
					response_error(clstate, 400);
					goto _done;
				}

				/*
				 * It's also strict to standard.
				 * No free form specifiers are permitted.
				 */
				s += CSTR_SZ("bytes=");
_rangeparser:			/* If came there from header, then the range is already here. */
				d = strchr(s, '-'); /* find dash */
				if (!d) {
					response_error(clstate, 400);
					goto _done;
				}
				*d = 0; d++;
				if (str_empty(d)) { /* Range: bytes=6144- */
					clstate->range_start = rh_str_fsize(s, &stoi);
					if (!str_empty(stoi)) {
						response_error(clstate, 400);
						goto _done;
					}
					if (clstate->range_start >= clstate->filesize) {
						d = NULL;
						rh_asprintf(&d, "bytes */%llu", clstate->filesize);
						add_header(&clstate->sendheaders,
							"Content-Range", d);
						pfree(d);

						response_error(clstate, 416);
						goto _done;
					}
					clstate->range_end = clstate->filesize;
				}
				else { /* Range: bytes=6144-8192 */
					clstate->range_start = rh_str_fsize(s, &stoi);
					if (!str_empty(stoi)) {
						response_error(clstate, 400);
						goto _done;
					}
					clstate->range_end = rh_str_fsize(d, &stoi)+1;
					if (!str_empty(stoi)) {
						response_error(clstate, 400);
						goto _done;
					}
					if (clstate->range_start >= clstate->filesize
					|| clstate->range_start > clstate->range_end) {
						d = NULL;
						rh_asprintf(&d, "bytes */%llu", clstate->filesize);
						add_header(&clstate->sendheaders,
							"Content-Range", d);
						pfree(d);

						response_error(clstate, 416);
						goto _done;
					}
					if (clstate->range_end > clstate->filesize)
						clstate->range_end = clstate->filesize;
				}

				s = NULL;
				rh_asprintf(&s, "bytes %llu-%llu/%llu",
					clstate->range_start,
					clstate->range_end > 0 ? clstate->range_end-1 : 0,
					clstate->filesize);
				add_header(&clstate->sendheaders, "Content-Range", s);
				rh_asprintf(&s, "%llu", clstate->range_end-clstate->range_start);
				add_header(&clstate->sendheaders, "Content-Length", s);
				pfree(s);
				response_ok(clstate, 206, YES);
			}
			else {
				s = NULL;
				rh_asprintf(&s, "%llu", clstate->filesize);
				add_header(&clstate->sendheaders, "Content-Length", s);
				response_ok(clstate, 200, YES); /* no range, just send headers */
			}

			if (clstate->method == REQ_METHOD_HEAD) goto _no_send;

			/* actually stream a file/partial file data, anything is inside clstate */
			do_stream_file(clstate);

_no_send:		/*
			 * Close the file.
			 * Why open if HEAD? Because to prove it can
			 * be read, so HEAD response will be actual.
			 */
			close(clstate->file_fd);
			clstate->file_fd = -1;

			/* done. */
			goto _done;
		}
	}
	/* directory operations */
	else {
		DIR *dp;
		struct dirent *de;
		struct stat stst;
		rh_yesno do_text = NO;
		rh_yesno no_dl_hints = NO;
		char *dpath = NULL;
		char *dname = NULL;
		char *dargs = NULL;
		size_t idx_from, idx_to, curr_idx;
		struct dir_items *di;
		char *entline, *mtime, *uname, *gname, *fsize;
		size_t xsz;

		/* POST is not permitted for directories */
		if (clstate->method > REQ_METHOD_HEAD) {
			add_header(&clstate->sendheaders, "Allow", "GET, HEAD");
			response_error(clstate, 405);
			goto _done;
		}

		/*
		 * Fixup HTTP path to contain last slash.
		 * Useful for logging and "Index of" string.
		 */
		x = strnlen(clstate->path, RH_XSALLOC_MAX);
		if (x > 0 && clstate->path[x-1] != '/')
			rh_astrcat(&clstate->path, "/");

		/* Same for prevpath (if there is any) */
		if (clstate->prevpath) {
			x = strnlen(clstate->prevpath, RH_XSALLOC_MAX);
			if (x > 0 && clstate->prevpath[x-1] != '/')
				rh_astrcat(&clstate->prevpath, "/");
		}

		/*
		 * But still pass a version without forward slash to verify_htaccess.
		 */
		s = rh_strdup(clstate->realpath);
		x = strnlen(s, RH_XSALLOC_MAX);
		/* x > 1: do not touch single "/" string. */
		if (x > 1 && s[x-1] == '/') s[x-1] = 0;
		rh_strlrep(s, rh_szalloc(s), "//", "/");

		/* Verify the user has access */
		err = verify_htaccess(clstate, s, clstate->httproot);
		pfree(s);
		if (err == HTA_REWRITE) goto _hta_rewrite;
		if (err > 0) {
			response_error(clstate, err);
			goto _done;
		}

		/* Search index file first */
		s = find_index_file(clstate->realpath);
		if (s) {
			/* Reinstall realpath pointer */
			pfree(clstate->realpath);
			clstate->realpath = s;
			rh_strlrep(clstate->realpath, rh_szalloc(clstate->realpath), "//", "/");
			clstate->filedir = PATH_IS_FILE;
			clstate->is_indx = YES;
			/* Send as regular file */
			goto _sendidx;
		}

		/* Indexing was forbidden by htaccess. */
		if (clstate->noindex == YES) {
			response_error(clstate, 403);
			goto _done;
		}

		/* No index - send directory listing */
		dp = opendir(clstate->realpath);
		if (!dp) {
			response_error(clstate, 403);
			goto _done;
		}

		if (stat(clstate->realpath, &stst) == -1) goto _nodlastmod;
		/* Add directory Last-Modified header */
		s = getsdate(stst.st_mtime, HTTP_DATE_FMT, YES);
		add_header(&clstate->sendheaders, "Last-Modified", s);
		pfree(s);

_nodlastmod:	/* In HTTP/1.0 and earlier chunked T.E. is NOT permitted. Turn off keep-alive. */
		if (!strcmp(clstate->protoversion, "1.0")
		|| !strcmp(clstate->protoversion, "0.9")) {
			clstate->is_keepalive = NO;
			delete_header(&clstate->sendheaders, "Keep-Alive");
		}

		/* Text only listing */
		s = client_arg("txt");
		if (s && !(!strcmp(s, "0"))) do_text = YES;

		/* No additional icon links, plain listing */
		if (do_text == NO) {
			s = client_arg("nodlh");
			if (s && !(!strcmp(s, "0"))) no_dl_hints = YES;
			if (no_dl_hints == NO) {
				s = client_header("x-ryshttpd-nodlh");
				if (s && !(!strcmp(s, "0"))) no_dl_hints = YES;
			}
			if (no_dl_hints == NO) {
				s = client_header("User-Agent");
				/* Make Wget life easier */
				if (s && (strstr(s, "Wget") || strstr(s, "wget")))
					no_dl_hints = YES;
			}
		}

		s = client_arg("idxfrom");
		if (s) {
			char *stoi;

			idx_from = rh_str_size(s, &stoi);
			if (!str_empty(stoi)) {
				response_error(clstate, 400);
				goto _done;
			}
		}
		else idx_from = NOSIZE;
		s = client_arg("idxto");
		if (s) {
			char *stoi;

			idx_to = rh_str_size(s, &stoi);
			if (!str_empty(stoi)) {
				response_error(clstate, 400);
				goto _done;
			}
		}
		else idx_to = idx_from;
		if ((idx_from != NOSIZE && idx_to == NOSIZE)
		|| (idx_from == NOSIZE && idx_to != NOSIZE)
		|| (idx_from > idx_to)) {
			response_error(clstate, 400);
			goto _done;
		}

		di_sortby = DI_SORTBY_NAME;
		di_reverse_sort = NO;
		s = client_arg("sortby");
		if (s) {
			if (!strcasecmp(s, "name")) di_sortby = DI_SORTBY_NAME;
			else if (!strcasecmp(s, "type")) di_sortby = DI_SORTBY_TYPE;
			else if (!strcasecmp(s, "size")) di_sortby = DI_SORTBY_SIZE;
			else if (!strcasecmp(s, "owner")
			|| !strcasecmp(s, "uid")) di_sortby = DI_SORTBY_OWNER;
			else if (!strcasecmp(s, "group")
			|| !strcasecmp(s, "gid")) di_sortby = DI_SORTBY_GROUP;
			else if (!strcasecmp(s, "time")
			|| !strcasecmp(s, "date")) di_sortby = DI_SORTBY_MTIME;
			else if (!strcasecmp(s, "none")) di_sortby = 0;
			else {
				response_error(clstate, 400);
				goto _done;
			}
		}
		s = client_arg("rsort");
		if (s && !(!strcmp(s, "0"))) di_reverse_sort = YES;

		/* File names may be encoded in UTF-8, so force it */
		add_header(&clstate->sendheaders, "Content-Type",
			do_text ? "text/plain; charset=utf-8" : "text/html; charset=utf-8");
		if (clstate->is_keepalive == YES) {
			/*
			 * Because I do not know how much I will write,
			 * I use chunked transfer encoding. But only in HTTP/1.1.
			 */
			add_header(&clstate->sendheaders, "Transfer-Encoding", "chunked");
		}
		/* Tell to never cache the result since user may wish to refresh it again */
		tell_never_cache(clstate);
		response_ok(clstate, 200, YES);
		if (clstate->method == REQ_METHOD_HEAD) goto _no_list;

		if (do_text == NO) {
			dpath = rh_strdup(clstate->prevpath ? clstate->prevpath : clstate->path);
			filter_special_htmlchars(&dpath);
			if (clstate->strargs) {
				s = rh_strdup(clstate->strargs);
				filter_special_htmlchars(&s);
				dargs = NULL;
				rh_asprintf(&dargs, "?%s", s);
				pfree(s);
			}
			else dargs = rh_strdup("");

			d = NULL;
			sz = rh_asprintf(&d, "<!DOCTYPE HTML>\n"
				"<html>\n"
				"<head>\n"
				"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\">\n"
				"<link rel=\"stylesheet\" href=\"%s/_rsrc/style.css\">\n"
				"<link rel=\"shortcut icon\" href=\"%s/favicon.ico\">\n"
				"<title>Index of %s%s</title>\n"
				"</head>\n"
				"<body>\n"
				"<h1>Index of %s%s</h1>\n"
				"<hr>\n<pre>\n<table>\n",
				ppath(clstate->prepend_path),
				ppath(clstate->prepend_path),
				ppath(clstate->prepend_path), dpath,
				ppath(clstate->prepend_path), dpath);
			sz = rh_strlrep(d, sz+1, "//", "/");
			response_chunk_length(clstate, sz);
			response_send_data(clstate, d, sz);
			response_chunk_end(clstate);
			pfree(d);
		}

		if (chdir(clstate->realpath) == -1) {
			/* This is stupid. */
			goto _failed_chdir;
		}

		if (do_text == NO) {
			d = NULL;
			sz = rh_asprintf(&d, "<tr><td id=\"name\"><a href=\"../%s\">../</a></td></tr>\n", dargs);

			response_chunk_length(clstate, sz);
			response_send_data(clstate, d, sz);
			response_chunk_end(clstate);
		}

		di = NULL;
		curr_idx = 0;
		while ((de = readdir(dp))) {
			if (!strcmp(de->d_name, ".")
			|| !strcmp(de->d_name, "..")
			|| strstr(de->d_name, rh_htaccess_name)) continue;

			/* Nobody wants to see useless errors, just hide them away */
			if (stat(de->d_name, &stst) == -1) continue;

			/* .htaccess hides these items away from listing. */
			if (clstate->hideindex_rgx
			&& regex_exec(clstate->hideindex_rgx, de->d_name) == YES)
				continue;

			if ((idx_from != NOSIZE && curr_idx < idx_from)
			|| (idx_to != NOSIZE && curr_idx > idx_to)) goto _inc_idx;

			sz = DYN_ARRAY_SZ(di);
			di = rh_realloc(di, (sz+1) * sizeof(struct dir_items));
			di[sz].it_name = rh_strdup(de->d_name);
			if (S_ISDIR(stst.st_mode)) {
				di[sz].it_type = PATH_IS_DIR;
				di[sz].it_size = (rh_fsize)0;
			}
			else {
				di[sz].it_type = PATH_IS_FILE;
				di[sz].it_size = (rh_fsize)stst.st_size;
			}
			di[sz].it_mode = stst.st_mode;
			di[sz].it_owner = stst.st_uid;
			di[sz].it_group = stst.st_gid;
			di[sz].it_mtime = stst.st_mtime;

_inc_idx:		curr_idx++;
		}

		if (di == NULL) {
_failed_chdir:		if (do_text == YES) {
				sz = CSTR_SZ("[Directory is empty]\n");
				response_chunk_length(clstate, sz);
				response_send_data(clstate, "[Directory is empty]\n", sz);
				response_chunk_end(clstate);
			}
			else {
				sz = CSTR_SZ("<tr><td><i><b>Directory is empty</b></i></td></tr>\n");
				response_chunk_length(clstate, sz);
				response_send_data(clstate,
					"<tr><td><i><b>Directory is empty</b></i></td></tr>\n", sz);
				response_chunk_end(clstate);
			}

			goto _no_dir_items;
		}

		sz = DYN_ARRAY_SZ(di);
		if (di_sortby > 0 && rh_no_dirsort == NO)
			qsort(di, sz, sizeof(struct dir_items), dir_sort_compare);

		for (x = 0; x < sz; x++) {
			entline = NULL;
			mtime = getsdate(di[x].it_mtime, rh_list_date_fmt, NO);
			uname = namebyuid(di[x].it_owner);
			gname = namebygid(di[x].it_group);

			if (di[x].it_type == PATH_IS_DIR) {
				if (do_text == YES) {
					xsz = rh_asprintf(&entline,
						"%04o\t%s\t%s\t0 (DIR)\t%s\t%s%s%s/\n",
						di[x].it_mode & ~S_IFMT, uname, gname, mtime,
						ppath(clstate->prepend_path), clstate->prevpath ? clstate->prevpath : clstate->path, di[x].it_name);
				}
				else {
					dname = rh_strdup(di[x].it_name);
					filter_special_htmlchars(&dname);

					xsz = rh_asprintf(&entline,
						"<tr>"
						"<td id=\"name\"><i><b><a href=\"%s%s%s/%s\">%s/</a></b></i></td>"
						"<td>0\t(DIR)</td><td>%s</td><td>%s</td><td>%s</td>"
						"</tr>\n",
						ppath(clstate->prepend_path), dpath, dname, dargs, dname,
						uname, gname, mtime);

					pfree(dname);
				}
			}
			else {
				fsize = rh_human_fsize(di[x].it_size);
				if (do_text == YES) {
					xsz = rh_asprintf(&entline,
						"%04o\t%s\t%s\t%llu (%s)\t%s\t%s%s%s\n",
						di[x].it_mode & ~S_IFMT, uname, gname,
						di[x].it_size, fsize, mtime,
						ppath(clstate->prepend_path), clstate->prevpath ? clstate->prevpath : clstate->path, di[x].it_name);
				}
				else {
					dname = rh_strdup(di[x].it_name);
					filter_special_htmlchars(&dname);

					if (no_dl_hints == YES) {
						xsz = rh_asprintf(&entline,
							"<tr>"
							"<td id=\"name\"><b><a href=\"%s%s%s\">%s</a></b></td>"
							"<td>%llu\t(%s)</td><td>%s</td><td>%s</td><td>%s</td>"
							"</tr>\n",
							ppath(clstate->prepend_path), dpath, dname, dname,
							di[x].it_size, fsize, uname, gname, mtime);

					}
					else {
						xsz = rh_asprintf(&entline,
							"<tr>"
							"<td id=\"name\"><b><a href=\"%s%s%s\">%s</a></b></td>"
							"<td>%llu\t(%s)</td><td>%s</td><td>%s</td><td>%s</td>"
							"<td><a href=\"%s%s%s?dl=1\" title=\"Download %s\"><img src=\"%s/_rsrc/download.png\" alt=\"Download %s\"></a></td>"
							"<td><a href=\"%s%s%s?vi=1\" title=\"View %s\"><img src=\"%s/_rsrc/view.png\" alt=\"View %s\"></a></td>"
							"</tr>\n",
							ppath(clstate->prepend_path), dpath, dname, dname,
							di[x].it_size, fsize, uname, gname, mtime,
							ppath(clstate->prepend_path), dpath, dname, dname, ppath(clstate->prepend_path), dname,
							ppath(clstate->prepend_path), dpath, dname, dname, ppath(clstate->prepend_path), dname);
					}

					pfree(dname);
				}
				pfree(fsize);
			}

			pfree(mtime);
			pfree(uname);
			pfree(gname);

			xsz = rh_strlrep(entline, xsz+1, "//", "/");
			response_chunk_length(clstate, xsz);
			response_send_data(clstate, entline, xsz);
			response_chunk_end(clstate);

			pfree(entline);
		}

		free_dir_items(di);

_no_dir_items:
		if (do_text == NO) {
			dname = rh_strdup(rh_ident);
			filter_special_htmlchars(&dname);

			d = NULL;
			sz = rh_asprintf(&d, "</table>\n<hr>\n<i><b>%s</b></i>\n", dname);
			response_chunk_length(clstate, sz);
			response_send_data(clstate, d, sz);
			response_chunk_end(clstate);
			pfree(d);
			sz = CSTR_SZ("</pre>\n</body>\n</html>\n");
			response_chunk_length(clstate, sz);
			response_send_data(clstate, "</pre>\n</body>\n</html>\n", sz);
			response_chunk_end(clstate);

			pfree(dname);
			pfree(dpath);
			pfree(dargs);
		}

		response_chunk_length(clstate, 0);
		response_chunk_end(clstate);
_no_list:	closedir(dp);
	}

	/*
	 * Reset client state, do not touch connection info.
	 * Restart if keepalive was requested, otherwise exit.
	 */
_done:	clstate->nr_requests++;
	write_log_line(clstate);
	if (clstate->is_keepalive) {
		/* Max. No of log bytes were already emitted, exit prematurely! */
		if (clinfo->maxlogsz != NOSIZE) {
			/* Minus one potential line. */
			if (clinfo->logwrit >= clinfo->maxlogsz - RH_ALLOC_MAX)
				goto _do_exit;
		}
		/* Max. No. of requests reached, drop the client. */
		if (clstate->nr_requests >= rh_client_keepalive_requests)
			goto _do_exit;
		/* Reset to empty state */
		reset_client_state(clstate);
		/* Reinstall keep alive timeout, so read from client would timeout */
		set_timeout_alarm(rh_client_keepalive_timeout);
		/* Start over reading another request */
		goto _start;
	}
	else {
_do_exit:	rh_exit(0);
	}
}
