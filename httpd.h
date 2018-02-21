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

#ifndef _RYSHTTPD_H
#define _RYSHTTPD_H

#define PROGRAM_NAME "ryshttpd"

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include "config.h"

#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/mman.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <sys/time.h>
#include <time.h>
#include <limits.h>
#include <libgen.h>
#include <regex.h>
#include <pwd.h>
#include <grp.h>
#include <locale.h>
#ifdef WITH_TLS
#define XMALLOC rh_malloc
#define XCALLOC rh_calloc
#define XREALLOC rh_realloc
#define XFREE rh_free
#define TLS_MALLOC rh_malloc
#define TLS_REALLOC rh_realloc
#define TLS_FREE pfree
#define TLS_AMALGAMATION
#include "tlse.h"
#define THIS_IS_TLS_CONN ((void *)0x443) /* A marker describing that it is a TLS connection. */
#else
#define TLSE_C
#define TLSE_H
#endif

enum { NO, YES };

#define NOSIZE  ((size_t)-1) /* NOt a SIZE */
#define NOFSIZE ((rh_fsize)-1) /* NOt a FileSIZE */

#define RH_XSALLOC_MAX 262144 /* max. amount of memory to scan */
#define RH_CLIENT_READ_SZ 32768 /* temporary to read request into, and IO pool */
#define RH_ALLOC_MAX 4096 /* usual max allocation size of single object like string */
#define RH_ALLOC_SMALL 128 /* small objects preallocation size limit */

#define STAT_ARRAY_SZ(x) (sizeof(x)/sizeof(*x))
#define DYN_ARRAY_SZ(x) (rh_szalloc(x)/sizeof(*x))
#define CSTR_SZ(x) (sizeof(x)-1)

#define ADDHALF_TO(x) ((x / 2) * 3)

/* only for rh_yesno types, boys and girls! */
#define FLIP_YESNO(x) do {		\
		if (x == YES) x = NO;	\
		else x = YES;		\
	} while (0)

#define HTTP_DATE_FMT "%a, %d %b %Y %H:%M:%S GMT"
#define LIST_DATE_FMT "%H:%M:%S %d%b%Y"
#define HTTP_REQUEST_MAX 4096
#define HTTP_REQHEAD_MAX 2048

typedef void (*sighandler_t)(int);
typedef unsigned long long rh_fsize;
typedef short rh_yesno;

extern char **environ;

extern char *progname;
extern pid_t svpid;

extern char *rh_hostnames;
extern char *rh_bindaddr4_s;
extern char *rh_bindaddr6_s;
extern char *rh_port_s;
#ifdef WITH_TLS
extern char *rh_tlsport_s;
#endif
extern char *rh_ident;
extern char *rh_root_dir;
extern char *rh_logfile;
extern char *rh_logfmt;
extern char *rh_timefmt;
#ifdef WITH_LIBMAGIC
extern char *rh_magicdb_path;
#endif
extern char *rh_indexes_pattern;
extern char *rh_chroot_dir;
extern char *rh_switch_user;
extern char *rh_switch_euser;
extern char *rh_switch_group;
extern char *rh_switch_egroup;
extern char *rh_switch_groups;
extern char *rh_cgi_execs;
extern char *rh_nhcgi_execs;
extern char *rh_cgieh_execs;
extern char *rh_cgiserver;
extern char *rh_cgi_path;
extern char *rh_xrealip;
extern char *rh_htaccess_name;
extern char *rh_dir_prepend_path;
#ifndef WITH_LIBMAGIC
extern char *rh_content_charset;
#endif
extern unsigned long rh_client_request_timeout;
extern unsigned long rh_client_keepalive_timeout;
extern size_t rh_client_keepalive_requests;
extern unsigned int rh_client_ipv6_subnet;
extern int rh_cgi_mode;
extern rh_yesno rh_follow_symlinks;
extern size_t rh_rdwr_bufsize;
extern rh_yesno rh_issuper;

extern void *rh_hostnames_rgx;
extern void *rh_cgiexecs_rgx;
extern void *rh_nhcgiexecs_rgx;
extern void *rh_cgiehexecs_rgx;

struct client_state; /* declared later */

#define RATELIM_START_CHUNKS 32 /* should be fully divisible */
#define RATELIM_TIME_CHUNK(nr) (1000000000UL / nr)
#define RATELIM_TIME_CHUNK_REM(nr, chunk, rem) ((RATELIM_TIME_CHUNK(nr)/chunk)*rem)

struct rate_limit {
	rh_fsize total; /* total bandwidth limit */
	rh_yesno calculated; /* if it was calculated, then do not touch it */
	size_t chunk; /* chunk size */
	size_t nr_chk; /* number of chunks per sec, starting from RATELIM_START_CHUNKS */
	/* the stuff below is for smaller than "chunk" chunks */
	size_t done; /* temporary: how many bytes already was done to trigger sleep */
	struct timespec doneacc; /* total small chunks done time */
};

struct client_info {
	/* Process and logging devices and bookkeeping */
	pid_t pid; /* This client child pid */
	int logfd; /* fd to logging pipe end, this is WR end */
	size_t logwrit; /* how much bytes already written to log pipe? */
	size_t maxlogsz; /* if != NOSIZE, then up to this size is possible to write */

	/* I/O information */
	int clfd; /* client fd to which writings are necessary */
#ifdef WITH_TLS
	struct TLSContext *svtls; /* server side TLSE context */
	struct TLSContext *cltls; /* client side TLSE context */
#endif
	struct rate_limit ralimitup; /* upload (from client) speed limit */
	struct rate_limit ralimitdown; /* download (to client) speed limit */

	/* Networking devices and information */
	int af; /* address family */
	void *sockaddr; /* raw accept'ed client sockaddr struct corresponding to family */
	socklen_t sockaddrlen; /* length of sockaddr structure */
	char *ipaddr; /* resolved numeric ip address */
	char *port; /* remote client port number */
	char *servport; /* server port that accepted connection */
};

typedef void (*rh_exit_cb)(int);
extern rh_exit_cb rh_atexit;

void rh_exit(int status);
void set_progname(const char *name);
void xerror(const char *f, ...);
void xerror_status(int status, const char *f, ...);
void rh_perror(const char *f, ...);
void xexits(const char *f, ...);
void xexits_status(int status, const char *f, ...);
char *rh_strerror(int err);

void usage(void);
void show_version(void);

void rh_vfsay(FILE *where, rh_yesno addnl, const char *fmt, va_list ap);
void rh_nvesay(const char *fmt, va_list ap);
void rh_nesay(const char *fmt, ...);
void rh_esay(const char *fmt, ...);
void rh_say(const char *fmt, ...);

void block_signals(rh_yesno block, int *n);

struct fmtstr_args;

#define APPEND_FSA(pfsa, pnr_fsa, sp, sz, sfmt, vdata)					\
	do {										\
		pfsa = rh_realloc(pfsa, (pnr_fsa+1) * sizeof(struct fmtstr_args));	\
		pfsa[pnr_fsa].spec = sp;						\
		pfsa[pnr_fsa].size = sz;						\
		pfsa[pnr_fsa].fmt = sfmt;						\
		pfsa[pnr_fsa].data = vdata;						\
		pnr_fsa++;								\
	} while (0)

void clear_environ(void);
void preset_fsa(struct fmtstr_args **fsa, size_t *nr_fsa, const struct client_state *clstate);

size_t rh_strltrep(char *str, size_t n, int *nr_reps, const char *from, const char *to);
size_t rh_strlrep(char *str, size_t n, const char *from, const char *to);
size_t rh_strrep(char *str, const char *from, const char *to);

void rh_memzero(void *p, size_t l);
rh_yesno memtest(void *p, size_t l, int c);
void *rh_memdup(const void *p, size_t sz);
char *rh_strndup(const char *s, size_t max);
char *rh_strdup(const char *s);
void *append_data(void *block, const void *data, size_t szdata);

void *rh_malloc(size_t n);
#ifdef WITH_TLS
void *rh_calloc(size_t x, size_t y);
#endif
void *rh_realloc(void *p, size_t n);
void rh_free(void *p);
#define pfree(p) do { rh_free(p); p = NULL; } while (0)
size_t rh_szalloc(const void *p);

rh_yesno isnum(const char *s, int sign);
int rh_fcntl(int fd, int cmd, int flags, rh_yesno set);
rh_yesno is_writable(const char *path);

#define PATH_IS_FILE 1
#define PATH_IS_DIR  2

char *rh_realpath(const char *path);
rh_yesno is_symlink(const char *path);
int file_or_dir(const char *path);
rh_yesno is_exec(const char *path);

void init_indexes(const char *idxstr);
char *find_index_file(const char *dir);

struct netaddr {
	int type;
	char addr[16];
	char saddr[INET6_ADDRSTRLEN];
	unsigned int pfx, pmax;
};

int rh_addr_type(const char *addr);
rh_yesno rh_parse_addr(const char *addr, struct netaddr *na);
rh_yesno rh_match_addr(const struct netaddr *n, const struct netaddr *a);

#define HTA_REWRITE 494

rh_yesno is_htaccess(const char *path);
int verify_htaccess(struct client_state *clstate, const char *path, const char *rootdir);

struct fmtstr_args {
	char *spec;
	size_t size;
	char *fmt;
	const void *data;
};

struct fmtstr_state {
	struct fmtstr_args *args;
	int nargs;
	const char *fmt;
	char *result;
	size_t result_sz;
	int nr_parsed;
	short trunc;
};

rh_yesno str_empty(const char *str);
size_t char_to_nul(char *s, size_t l, char c);
size_t rh_strlcpy_real(char *dst, const char *src, size_t size);
size_t rh_strlcpy(char *d, const char *s, size_t n);
rh_yesno is_fmtstr(const char *s);
void nuke_fmtstr_templates(char *line, size_t szline);
char *parse_fmtstr(struct fmtstr_state *fst);
size_t shrink_dynstr(char **s);
void rh_astrcat(char **d, const char *s);
void rh_prepend_str(char **d, const char *s);
int rh_snprintf(char *s, size_t n, const char *fmt, ...);
int rh_vsnprintf(char *s, size_t n, const char *fmt, va_list ap);
int rh_vasprintf(char **s, const char *fmt, va_list ap);
int rh_asprintf(char **s, const char *fmt, ...);
rh_yesno getxchr(char *chr, const char *s);
void parse_escapes(char *str, size_t n);
size_t filter_dotdots(char *str, size_t strsz);
void unquote(char *str, size_t strsz);

void urldecode(char *str, size_t n);
char *urlencode(const char *str);

rh_yesno is_comment(const char *s);
void *load_config(int fd);
char *get_config_line(void *config);
void free_config(void *config);

#define RH_REGEX_MAX_GROUPS 32

void *regex_compile(const char *pattern, rh_yesno nocase, rh_yesno pmatch);
rh_yesno regex_exec(const void *regex, const char *string);
char *regex_get_pattern(const void *regex);
char *regex_get_match(const void *regex, const char *string, size_t idx);
rh_yesno regex_is_error(const void *regex);
char *regex_error(const void *regex);
void regex_xexits(const void *regex);
void regex_free(void *regex);

rh_yesno getsdate_r(time_t t, const char *fmt, rh_yesno gmt, char *str, size_t szstr);
char *getsdate(time_t t, const char *fmt, rh_yesno gmt);
time_t getdatetime_r(char *date, size_t szdate, const char *fmt);
time_t getdatetime(char **date, const char *fmt);

uid_t uidbyname(const char *name);
gid_t gidbyuid(uid_t uid);
gid_t gidbyname(const char *name);
int getugroups(const char *name, gid_t gr, gid_t *grps, int *ngrps);
char *namebyuid(uid_t uid);
char *namebygid(gid_t gid);
void *init_user_switch(
	const char *user, const char *group,
	const char *euser, const char *egroup,
	const char *groups);
void user_switch_setid_policy(void *uswitch, rh_yesno nosetuid, rh_yesno nosetgid);
void apply_user_switch(const void *uswitch);
rh_yesno user_switch_issuper(const void *uswitch);
void free_user_switch(void *uswitch);

rh_fsize rh_fdsize(int fd);

rh_fsize rh_str_fsize(const char *s, char **stoi);
size_t rh_str_size(const char *s, char **stoi);
long rh_str_long(const char *s, char **stoi);
int rh_str_int(const char *s, char **stoi);
char *rh_human_fsize(rh_fsize fsize);
rh_fsize rh_str_human_fsize(const char *s, char **stoi);

#define IOS_ALL_OK	0
#define IOS_READ_ERROR	1
#define IOS_WRITE_ERROR	2
#define IOS_SEEK_ERROR	3

typedef size_t (*io_read_fn)(void *, void *, size_t);
typedef size_t (*io_write_fn)(void *, const void *, size_t);
typedef rh_fsize (*io_seek_fn)(void *, rh_fsize);

struct io_stream_args {
	io_read_fn rdfn; /* reading function pointer */
	io_write_fn wrfn; /* writing function pointer */
	io_seek_fn skfn; /* seeking function pointer */
	void *fn_args; /* data required for functions above */
	void *workbuf; /* temporary rw buffer */
	size_t wkbufsz; /* size of workbuf */
	rh_fsize file_size; /* file size, to verify */
	rh_fsize start_from; /* seek to this offset */
	rh_fsize read_to; /* read to this offset */
	rh_fsize nr_written; /* how much was written */
	int error; /* actual system error */
	int status; /* IOS_* flag of io request */
};

size_t io_read_data(int fd, void *data, size_t szdata, rh_yesno noretry, size_t *rdd);
size_t io_write_data(int fd, const void *data, size_t szdata, rh_yesno noretry, size_t *wrd);
rh_yesno io_stream_file(struct io_stream_args *iosd_params);

#ifdef WITH_TLS
size_t TLS_send_pending(int fd, struct TLSContext *tlsctx);
rh_yesno TLS_parsemsg(struct TLSContext *tlsctx, int fd, void *tmp, size_t tsz);
size_t TLS_read(struct TLSContext *tlsctx, int fd, void *data, size_t szdata);
size_t TLS_write(struct TLSContext *tlsctx, int fd, const void *data, size_t szdata);
#endif

size_t io_recv_data(struct client_info *clinfo, void *data, size_t szdata, rh_yesno noretry, rh_yesno nosleep);
size_t io_send_data(struct client_info *clinfo, const void *data, size_t szdata, rh_yesno noretry, rh_yesno nosleep);

char *getmyhostname(void);
rh_yesno resolve_ip(int af, const void *sockaddr, socklen_t sockaddrlen, char **ipaddr);
rh_yesno resolve_port(int af, const void *sockaddr, socklen_t sockaddrlen, char **port);

#ifdef WITH_LIBMAGIC
rh_yesno init_magic_db(void);
char *get_mime_fd(int fd, void *tmp, size_t tsz);
#else
void init_mime_regex(void);
char *get_mime_filename(const char *filename);
#endif

/* these three are opaque - their machinery is hidden inside. */
void add_client(pid_t pid, int logfd, const char *ipaddr);
int get_client_logfd(pid_t pid);
void delete_client(pid_t pid);
size_t count_clients(const char *ipaddr);

#define RESTYPE_PATH 1
#define RESTYPE_NAME 2
#define RESTYPE_ARGS 3

struct embedded_resource {
	char *path; /* exact virtual file path which will be served from resource instead.
		NULL hides resource from public access, but "args" may expose it again.
		Error pages have both "path" and "args" set to NULL, and have only "name" set. */
	char *name; /* basename of path. Useful for error pages.
		Even if your resource is hidden or secret, please
		set this to a meaningful string. See client.c for details. */
	char *args; /* sent only if this QUERY_STRING is matched.
		If NULL, then strargs can be any, and resource will be matched and sent.
		With NULL "path", matched and viewed only by "args". Useful for secrets.
		Both "path" and "args" require path and strargs to match. */
	char *mimetype; /* it's mime type (exact) to be sent */
	rh_yesno is_static; /* should not be cloned and touched, mainly because it's either
		a binary resource, or there is nothing to edit inside it really. */
	time_t lastmod; /* last modified (dummy) timestamp. */

	void *data; /* actual resource data */
	size_t szdata; /* size of the resource data */
};

const struct embedded_resource *find_resource(int restype, const char *str);
const struct embedded_resource *find_resource_args(const char *path, const char *args);
struct embedded_resource *clone_resource(const struct embedded_resource *rsrc);
rh_yesno resource_prepend_path(struct embedded_resource *rsrc, const char *ppath);
void free_resource(struct embedded_resource *rsrc);

struct http_header {
	char *name; /* name of header */
	char *value; /* it's value */
};

struct http_arg {
	char *name; /* name of argument */
	char *value; /* it's value */
};

struct response_status {
	int status; /* integer http status code, e.g. 404 */
	const char *response; /* textual line to be sent, e.g. "404 Not Found".
		Also this status code is displayed on a error page. */
};

void response_chunk_length(struct client_state *clstate, size_t length);
void response_chunk_end(struct client_state *clstate);
void response_error(struct client_state *clstate, int status);
void response_ok(struct client_state *clstate, int status, rh_yesno end_head);
size_t response_recv_data(struct client_state *clstate, void *data, size_t szdata);
void response_send_data(struct client_state *clstate, const void *data, size_t szdata);

#define REQ_METHOD_GET  1
#define REQ_METHOD_HEAD 2
#define REQ_METHOD_POST 3

#define CGI_MODE_REGULAR 1
#define CGI_MODE_NOHEADS 2
#define CGI_MODE_ENDHEAD 3

/* keep in sync with reset_client_state@client.c */
struct client_state {
	/* Connection, state and keepalive info. Not touched by reset_client_state. */
	struct client_info *clinfo; /* connection info supplied */
	char *ipaddr; /* for xrealip: if none is used, then it is set to clinfo->ipaddr,
			if xrealip, then it contains address told by proxier to us,
			but clinfo->ipaddr always holds _real_ socket address. */
	size_t nr_requests; /* No. of requests processed. */
	rh_yesno is_keepalive; /* do not write log on empty requests */
	rh_yesno xrealip_authed; /* is client acting as frontend? */

	/* Client time. */
	time_t request_time; /* time when we taken client request to process. */
	char *request_date; /* rh_timefmt formatted date, for logging */

	/* Client supplied unparsed/parsed info */
	void *tail; /* data part supplied by client after "\r\n\r\n". Useful for CGI POST. */
	size_t sztail; /* if already resized, then tail is of this size. */
	char **request_lines; /* clean full copy of request lines, incl. method line */
	rh_yesno is_crlf; /* response: lines must end with "\r\n" */
	int method; /* GET or HEAD */
	char *request; /* usually path. Can contain arguments (after '?'). */
	char *protoversion; /* http protocol version requested, for response */
	char *path; /* urldecoded, filtered path of interest, free of any args */
	char *strargs; /* only arguments without leading '?', if any.
		filtered off insecure paths. */
	struct http_arg *args; /* parsed arguments above */
	struct http_header *headers; /* parsed client headers */

	/* Our private info necessary to provide a good response */
	char *realpath; /* resolved path with rh_realpath */
	int filedir; /* resolved as file or directory? */
	int file_fd; /* if file, then this is it's open fd for IO ops */
	rh_yesno is_exec; /* if file, will it be executed? */
	rh_yesno is_rsrc; /* it was a fake file: internal resource. */
	rh_yesno is_indx; /* set if was redirected by index regexmatch */
	int cgi_mode; /* CGI mode of operation: regular, NoHeaders */
	void *workbuf; /* response IO: temporary to read into */
	size_t wkbufsz; /* size of workbuf */
	rh_fsize filesize; /* measured file size, for direct files */
	rh_fsize range_start, range_end; /* for partial transfers */
	rh_fsize recvbytes; /* how many bytes were received already */
	rh_fsize sentbytes; /* how many bytes were sent already */
	int iostate; /* result of io_send_file work */
	int ioerror; /* set if there was an OS error while io_send_file work */
	struct http_header *sendheaders; /* additional headers which response routine must send */

	/* .htaccess related items */
	rh_yesno was_rewritten; /* single rewrite, without recursion, was matched before */
	rh_yesno noindex; /* htaccess forbids to index this directory */
	void *hideindex_rgx; /* htaccess "hideindex" regex matching data */

	/* Response status */
	char *status;

	/* Alternative log line string, for empty requests */
	char *altlogline;

	/* Prepend this path to all emitted content, if behind path appending frontend */
	char *prepend_path;
};

struct http_header *parse_headers(char *const *headers, size_t start, size_t end);
void add_header(struct http_header **hdrlist, const char *name, const char *value);
void delete_header(struct http_header **hdrlist, const char *name);
struct http_header *find_header(struct http_header *hdrlist, const char *name);
char *find_header_value(struct http_header *hdrlist, const char *name);
size_t headers_fmtstr_parse(struct http_header *hdrlist, char *line, size_t szline, const char *rpl);

struct http_arg *parse_args(const char *args);
struct http_arg *find_arg(struct http_arg *args, const char *name);
char *find_arg_value(struct http_arg *args, const char *name);
size_t args_fmtstr_parse(struct http_arg *args, char *line, size_t szline, const char *rpl);

void write_log_line(struct client_state *clstate);

void run_client(struct client_info *clinfo);

#endif
