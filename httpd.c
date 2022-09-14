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

char *progname;
pid_t svpid;

char *rh_hostnames;
char *rh_bindaddr4_s;
char *rh_bindaddr6_s;
char *rh_port_s;
char *rh_unixsock_path;
char *rh_unixsock_mode;
char *rh_unixsock_user;
char *rh_unixsock_group;
char *rh_ident;
char *rh_root_dir;
static char *rh_logfile_fmt;
char *rh_logfile;
char *rh_logfmt;
char *rh_timefmt;
char *rh_indexes_s;
#ifdef WITH_LIBMAGIC
char *rh_magicdb_path;
#endif
char *rh_chroot_dir;
char *rh_switch_user;
char *rh_switch_euser;
char *rh_switch_group;
char *rh_switch_egroup;
char *rh_switch_groups;
char *rh_cgi_execs;
char *rh_nhcgi_execs;
char *rh_cgieh_execs;
char *rh_cgi_path;
char *rh_cgiserver;
char **rh_xrealips;
char *rh_htaccess_name;
char *rh_dir_prepend_path;
#ifndef WITH_LIBMAGIC
char *rh_content_charset;
#endif
char *rh_list_date_fmt;
unsigned long rh_client_request_timeout = RH_DEFAULT_REQUEST_TIMEOUT;
unsigned long rh_client_keepalive_timeout = RH_DEFAULT_KEEPALIVE_TIMEOUT;
unsigned long rh_client_receive_timeout = RH_DEFAULT_RECEIVE_TIMEOUT;
unsigned long rh_client_send_timeout = RH_DEFAULT_SEND_TIMEOUT;
size_t rh_client_keepalive_requests = RH_DEFAULT_KEEPALIVE_REQUESTS;
unsigned int rh_client_ipv6_subnet = 64;
rh_yesno rh_follow_symlinks;
int rh_cgi_mode = CGI_MODE_REGULAR;
size_t rh_rdwr_bufsize = RH_CLIENT_READ_SZ;
static size_t log_bufsize = ADDHALF_TO(RH_CLIENT_READ_SZ);
static rh_yesno switch_user_on_fork;
static size_t client_connections_limit = RH_DEFAULT_CONNECTIONS_LIMIT;
static size_t client_all_connections_limit = RH_DEFAULT_ALL_CONNECTIONS_LIMIT;
static rh_fsize ratelimit_up = NOFSIZE;
static rh_fsize ratelimit_down = NOFSIZE;
static rh_yesno no_daemonise;
static rh_yesno ipv4_only;
static rh_yesno do_logrotate;
static rh_yesno drop_setuid;
static rh_yesno drop_setgid;
rh_yesno rh_issuper;
rh_yesno rh_insecure_htaccess;
rh_yesno rh_regex_no_case;
rh_yesno rh_htaccess_regex_no_case;
rh_yesno rh_no_dirsort;
rh_yesno rh_try_shell_exec;
rh_yesno rh_secure_httproot;
rh_yesno rh_allow_tar;
useconds_t rh_oom_timer;
unsigned long rh_oom_max_attempts;
int rh_on_fs_error;
rh_yesno rh_no_cache_headers;

void *rh_indexes_rgx;
void *rh_hostnames_rgx;
void *rh_cgiexecs_rgx;
void *rh_nhcgiexecs_rgx;
void *rh_cgiehexecs_rgx;

static int sv4fd = -1;
static struct sockaddr_in sv4addr;
static int sv6fd = -1;
static struct sockaddr_in6 sv6addr;
static int usfd = -1;
static struct sockaddr_un usaddr;
static struct pollfd svfds[3];

static int svlogfd;
static void *svlogln;

static rh_yesno in_exit;

static void do_daemonise(void)
{
	pid_t pid, sid;
	int i;

	pid = fork();
	if (pid < 0)
		exit(-1);
	if (pid > 0)
		exit(0);

	sid = setsid();
	if (sid < 0)
		exit(-1);

	close(0);
	close(1);
	close(2);
	for (i = 0; i < 3; i++)
		open("/dev/null", O_RDWR);
}

static void manage_clients(int sig);

static void server_atexit(int status)
{
	if (svlogfd != -1) close(svlogfd);
	if (sv4fd != -1) close(sv4fd);
	if (sv6fd != -1) close(sv6fd);
	if (usfd != -1) {
		close(usfd);
		if (rh_unixsock_path[0] != '@') unlink(rh_unixsock_path);
	}
}

static void signal_exit(int sig)
{
	block_signals(YES, sig, 0);
	in_exit = YES;
	manage_clients(sig);
	xexits("server: exited by signal %d", sig);
}

static void filter_log_simple(char *logln, size_t szlogln)
{
	size_t x;
	char chr[2];

	if (szlogln == 0) return;

	chr[1] = 0;
	for (x = 1; x < 32; x++) {
_last:		if ((char)x == '\n') continue;
		chr[0] = (char)x;
		if (memchr(logln, x, szlogln)) {
			rh_strlrep(logln, szlogln, chr, ".");
		}
		if (x == 127) return;
	}

	x = 127;
	goto _last;
}

static void logrotate_on_signal(int sig)
{
	block_signals(YES, SIGHUP, SIGCHLD, 0);

	getdatetime_r(rh_logfile, RH_ALLOC_MAX, rh_logfile_fmt);

	if (svlogfd != 1) close(svlogfd);
	svlogfd = open(rh_logfile, O_CREAT|O_WRONLY|O_APPEND, 0600);
	if (svlogfd == -1) {
		rh_perror("logrotate to %s failed, redirecting to stdout", rh_logfile);
		svlogfd = 1;
		rh_strlcpy(rh_logfile, "<stdout>", RH_ALLOC_MAX);
	}
	if (rh_fcntl(svlogfd, F_SETFD, FD_CLOEXEC, YES) == -1) {
		rh_perror("logrotate: setting CLOEXEC on %s, redirecting to stdout", rh_logfile);
		if (svlogfd != 1) close(svlogfd);
		svlogfd = 1;
		rh_strlcpy(rh_logfile, "<stdout>", RH_ALLOC_MAX);
	}

	block_signals(NO, SIGHUP, SIGCHLD, 0);
}

static void manage_clients(int sig)
{
	struct pollfd polldf;
	int logfd;
	pid_t pid;
	size_t sz, x, y;

	block_signals(YES, SIGCHLD, 0);

	sz = rh_szalloc(svlogln);
	while (1) {
		pid = waitpid(-1, NULL, (in_exit == YES) ? 0 : WNOHANG);
		if (pid <= 0) break;
		logfd = get_client_logfd(pid);
		if (logfd != -1) {
			polldf.fd = logfd;
			polldf.events = POLLIN;
_again:			if (poll(&polldf, 1, -1) == -1) {
				if (errno == EINTR) goto _again;
				goto _closefd;
			}
			if (polldf.revents) {
				y = 0;
				x = io_read_data(logfd, svlogln, sz-1, NO, &y);
				if (x == 0 || x == NOSIZE) x = y;
				if (y == 0) goto _closefd;
				filter_log_simple(svlogln, x);
				io_write_data(svlogfd, svlogln, x, NO, NULL);
			}
_closefd:		close(logfd);
		}
		delete_client(pid);
	}

	block_signals(NO, SIGCHLD, 0);
}

#define SETOPT(s, d) do { pfree(s); s = rh_strdup(d); } while (0)
int main(int argc, char **argv)
{
	int c;
	char *s, *d, *t, *p, *T, *stoi;
	char *lr_fpath, *lr_path, *lr_name, *lr_args, *lr_mimetype;
	socklen_t unl;

	svpid = getpid();
	set_progname(*argv);

	setlocale(LC_ALL, "C");

	for (c = 1; c < NSIG; c++) {
		if (c == SIGCHLD) signal(c, manage_clients);
		else if (c == SIGCONT || c == SIGHUP) signal(c, SIG_IGN);
		else signal(c, signal_exit);
	}

	rh_atexit = server_atexit;

	rh_port_s = rh_strdup(RH_DEFAULT_PORT);
	rh_ident = rh_strdup(RH_DEFAULT_IDENT);
	rh_indexes_s = rh_strdup(RH_DEFAULT_INDEXES);
	rh_htaccess_name = rh_strdup(RH_DEFAULT_HTACCESS_NAME);
	rh_cgi_execs = rh_strdup(RH_DEFAULT_CGI_EXECS);
	rh_nhcgi_execs = rh_strdup(RH_DEFAULT_NHCGI_EXECS);
	rh_cgieh_execs = rh_strdup(RH_DEFAULT_CGIEH_EXECS);
	rh_cgi_path = rh_strdup(RH_DEFAULT_CGI_PATH);
	rh_logfile = rh_malloc(RH_ALLOC_MAX);
	rh_logfmt = rh_strdup(RH_DEFAULT_LOG_FORMAT);
	rh_list_date_fmt = rh_strdup(LIST_DATE_FMT);

	while ((c = getopt(argc, argv, "hr:4p:U:l:O:FR:V")) != -1) {
		switch (c) {
			case 'r': SETOPT(rh_root_dir, optarg); break;
			case '4': FLIP_YESNO(ipv4_only); break;
			case 'U':
				if (strchr(optarg, ':') && optarg[0] != '@') {
					pfree(rh_unixsock_path);
					pfree(rh_unixsock_mode);
					pfree(rh_unixsock_user);
					pfree(rh_unixsock_group);
					T = rh_strdup(optarg);
					s = d = T; t = NULL;
					while ((s = strtok_r(d, ":", &t))) {
						if (d) d = NULL;

						if (!rh_unixsock_path) SETOPT(rh_unixsock_path, s);
						else if (!rh_unixsock_mode) SETOPT(rh_unixsock_mode, s);
						else if (!rh_unixsock_user) SETOPT(rh_unixsock_user, s);
						else if (!rh_unixsock_group) SETOPT(rh_unixsock_group, s);
						else break;
					}
					pfree(T);
				}
				else SETOPT(rh_unixsock_path, optarg);
				break;
			case 'p': SETOPT(rh_port_s, optarg); break;
			case 'l': SETOPT(rh_logfile_fmt, optarg); break;
			case 'F': FLIP_YESNO(no_daemonise); break;
			case 'R':
				lr_fpath = lr_path = lr_name = lr_args = lr_mimetype = NULL;
				T = rh_strdup(optarg);
				s = d = T; t = NULL;
				while ((s = strtok_r(d, ":", &t))) {
					if (d) d = NULL;

					if (!lr_fpath) lr_fpath = s;
					else if (!lr_path) lr_path = s;
					else if (!lr_name) lr_name = s;
					else if (!lr_args) lr_args = s;
					else if (!lr_mimetype) lr_mimetype = s;
					else break;
				}
				if (!lr_fpath || !lr_path
				|| !lr_name || !lr_args || !lr_mimetype)
					xexits("-R: all fields must be specified");
				if (load_user_resource(lr_fpath, lr_path, lr_name, lr_args, lr_mimetype) == NO)
					xerror("%s: cannot load resource from file", lr_fpath);
				pfree(T);
				break;
			case 'O':
				T = rh_strdup(optarg);
				s = d = T; t = NULL;
				while ((s = strtok_r(d, ",", &t))) {
					if (d) d = NULL;

					p = strchr(s, '=');
					if (p) {
						*p = 0;
						p++;
					}
					else p = s;

					if (!strcmp(s, "hostnames")) SETOPT(rh_hostnames, p);
					else if (!strcmp(s, "indexes")) SETOPT(rh_indexes_s, p);
					else if (!strcmp(s, "bindto4")) SETOPT(rh_bindaddr4_s, p);
					else if (!strcmp(s, "bindto6")) SETOPT(rh_bindaddr6_s, p);
					else if (!strcmp(s, "ident")) SETOPT(rh_ident, p);
#ifdef WITH_LIBMAGIC
					else if (!strcmp(s, "magicdb")) SETOPT(rh_magicdb_path, p);
#endif
					else if (!strcmp(s, "chroot")) SETOPT(rh_chroot_dir, p);
					else if (!strcmp(s, "forkuser")) FLIP_YESNO(switch_user_on_fork);
					else if (!strcmp(s, "user")) SETOPT(rh_switch_user, p);
					else if (!strcmp(s, "euser")) SETOPT(rh_switch_euser, p);
					else if (!strcmp(s, "group")) SETOPT(rh_switch_group, p);
					else if (!strcmp(s, "egroup")) SETOPT(rh_switch_egroup, p);
					else if (!strcmp(s, "groups")) SETOPT(rh_switch_groups, p);
					else if (!strcmp(s, "drop_setid")) {
						FLIP_YESNO(drop_setuid);
						FLIP_YESNO(drop_setgid);
					}
					else if (!strcmp(s, "drop_setuid")) FLIP_YESNO(drop_setuid);
					else if (!strcmp(s, "drop_setgid")) FLIP_YESNO(drop_setgid);
					else if (!strcmp(s, "logformat")) SETOPT(rh_logfmt, p);
					else if (!strcmp(s, "timeformat")) SETOPT(rh_timefmt, p);
					else if (!strcmp(s, "cgiexecs")) SETOPT(rh_cgi_execs, p);
					else if (!strcmp(s, "nhcgiexecs")) SETOPT(rh_nhcgi_execs, p);
					else if (!strcmp(s, "cgiehexecs")) SETOPT(rh_cgieh_execs, p);
					else if (!strcmp(s, "cgipath")) SETOPT(rh_cgi_path, p);
					else if (!strcmp(s, "cgiserver")) SETOPT(rh_cgiserver, p);
					else if (!strcmp(s, "cgimode")) {
						if (!strcmp(p, "regular"))
							rh_cgi_mode = CGI_MODE_REGULAR;
						else if (!strcmp(p, "noheaders"))
							rh_cgi_mode = CGI_MODE_NOHEADS;
						else if (!strcmp(p, "noendhead"))
							rh_cgi_mode = CGI_MODE_ENDHEAD;
						else xexits("cgimode: must be one of "
							"\"regular\", \"noheaders\", "
							"\"noendhead\".");
					}
					else if (!strcmp(s, "xrealip")) {
						size_t isz = DYN_ARRAY_SZ(rh_xrealips);
						rh_xrealips = rh_realloc(rh_xrealips, (isz+1) * sizeof(char *));
						rh_xrealips[isz] = rh_strdup(p);
					}
					else if (!strcmp(s, "htaccess")) SETOPT(rh_htaccess_name, p);
					else if (!strcmp(s, "logrotate")) FLIP_YESNO(do_logrotate);
					else if (!strcmp(s, "dir_prepend_path")) SETOPT(rh_dir_prepend_path, p);
#ifndef WITH_LIBMAGIC
					else if (!strcmp(s, "content_charset")) SETOPT(rh_content_charset, p);
#endif
					else if (!strcmp(s, "list_date_format")) SETOPT(rh_list_date_fmt, p);
					else if (!strcmp(s, "follow_symlinks")) FLIP_YESNO(rh_follow_symlinks);
					else if (!strcmp(s, "insecure_htaccess")) FLIP_YESNO(rh_insecure_htaccess);
					else if (!strcmp(s, "no_cache_headers")) FLIP_YESNO(rh_no_cache_headers);
					else if (!strcmp(s, "regex_no_case")) {
						FLIP_YESNO(rh_regex_no_case);
						rh_htaccess_regex_no_case = rh_regex_no_case;
					}
					else if (!strcmp(s, "no_dirsort")) FLIP_YESNO(rh_no_dirsort);
					else if (!strcmp(s, "try_shell_exec")) FLIP_YESNO(rh_try_shell_exec);
					else if (!strcmp(s, "secure_httproot")) FLIP_YESNO(rh_secure_httproot);
					else if (!strcmp(s, "allow_tar")) FLIP_YESNO(rh_allow_tar);
					else if (!strcmp(s, "rdwr_bufsize")) {
						rh_rdwr_bufsize = rh_str_size(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid rdwr buffer size", p);
						if (rh_rdwr_bufsize < RH_ALLOC_SMALL
						|| rh_rdwr_bufsize > RH_XSALLOC_MAX)
							xexits("%s: invalid rdwr buffer size", p);
					}
					else if (!strcmp(s, "log_bufsize")) {
						log_bufsize = rh_str_size(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid log buffer size", p);
						if (log_bufsize < RH_ALLOC_SMALL
						|| log_bufsize > RH_XSALLOC_MAX)
							xexits("%s: invalid log buffer size", p);
					}
					else if (!strcmp(s, "max_client_connections")) {
						client_connections_limit = rh_str_size(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid max connections number", p);
					}
					else if (!strcmp(s, "max_all_client_connections")) {
						client_all_connections_limit = rh_str_size(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid max all connections number", p);
					}
					else if (!strcmp(s, "client_ipv6_subnet")) {
						rh_client_ipv6_subnet = rh_str_int(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid ipv6 subnet", p);
						if (rh_client_ipv6_subnet > 128)
							xexits("%s: invalid ipv6 subnet", p);
					}
					else if (!strcmp(s, "request_timeout")) {
						rh_client_request_timeout = rh_str_long(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid value, should be seconds number", p);
					}
					else if (!strcmp(s, "receive_timeout")) {
						rh_client_receive_timeout = rh_str_long(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid value, should be seconds number", p);
					}
					else if (!strcmp(s, "send_timeout")) {
						rh_client_send_timeout = rh_str_long(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid value, should be seconds number", p);
					}
					else if (!strcmp(s, "keepalive_timeout")) {
						rh_client_keepalive_timeout = rh_str_long(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid value, should be seconds number", p);
					}
					else if (!strcmp(s, "keepalive_requests")) {
						rh_client_keepalive_requests = rh_str_size(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid value of max requests", p);
					}
					else if (!strcmp(s, "ratelimit")) {
						ratelimit_up = rh_str_human_fsize(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid rate limit value", p);
						ratelimit_down = ratelimit_up;
					}
					else if (!strcmp(s, "ratelimit_up")) {
						ratelimit_up = rh_str_human_fsize(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid upload rate limit value", p);
					}
					else if (!strcmp(s, "ratelimit_down")) {
						ratelimit_down = rh_str_human_fsize(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid download rate limit value", p);
					}
					else if (!strcmp(s, "oom_timer")) {
						rh_oom_timer = (useconds_t)rh_str_long(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid OOM timer value", p);
					}
					else if (!strcmp(s, "oom_max_attempts")) {
						rh_oom_max_attempts = (unsigned long)rh_str_long(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid OOM max attempts value", p);
					}
					else if (!strcmp(s, "on_fs_error")) {
						rh_on_fs_error = rh_str_int(p, &stoi);
						if (!str_empty(stoi))
							xexits("%s: invalid default filesystem error code", p);
					}
					else xexits("%s: unknown option", s);
				}
				pfree(T);
				break;
			case 'V': show_version(); break;
			case 'h':
			default: usage(); break;
		}
	}

	if (rh_logfmt) parse_escapes(rh_logfmt, rh_szalloc(rh_logfmt));
	if (rh_timefmt) parse_escapes(rh_timefmt, rh_szalloc(rh_timefmt));

	if (rh_hostnames) {
		rh_hostnames_rgx = regex_compile(rh_hostnames, rh_regex_no_case, NO, NO);
		if (regex_is_error(rh_hostnames_rgx))
			regex_xexits(rh_hostnames_rgx);
	}

	if (!rh_root_dir) xexits("root directory is required!");
	rh_strlrep(rh_root_dir, rh_szalloc(rh_root_dir), "//", "/");

#ifdef WITH_LIBMAGIC
	if (init_magic_db() == NO) xerror("init libmagic");
#else
	init_mime_regex();
#endif

	rh_indexes_rgx = regex_compile(rh_indexes_s, rh_regex_no_case, NO, NO);
	if (regex_is_error(rh_indexes_rgx))
		regex_xexits(rh_indexes_rgx);

	rh_cgiexecs_rgx = regex_compile(rh_cgi_execs, rh_regex_no_case, NO, NO);
	if (regex_is_error(rh_cgiexecs_rgx))
		regex_xexits(rh_cgiexecs_rgx);

	rh_nhcgiexecs_rgx = regex_compile(rh_nhcgi_execs, rh_regex_no_case, NO, NO);
	if (regex_is_error(rh_nhcgiexecs_rgx))
		regex_xexits(rh_nhcgiexecs_rgx);

	rh_cgiehexecs_rgx = regex_compile(rh_cgieh_execs, rh_regex_no_case, NO, NO);
	if (regex_is_error(rh_cgiehexecs_rgx))
		regex_xexits(rh_cgiehexecs_rgx);

	if (rh_logfile_fmt) {
		svlogln = rh_malloc(log_bufsize);
		if (!strcmp(rh_logfile_fmt, "-")) {
			rh_strlcpy(rh_logfile, "<stdout>", RH_ALLOC_MAX);
			svlogfd = 1;
		}
		else {
			getdatetime_r(rh_logfile, RH_ALLOC_MAX, rh_logfile_fmt);
			svlogfd = open(rh_logfile, O_CREAT|O_WRONLY|O_APPEND, 0600);
			if (svlogfd == -1) xerror("%s", rh_logfile);
			if (rh_fcntl(svlogfd, F_SETFD, FD_CLOEXEC, YES) == -1)
				xerror("setting CLOEXEC on %s", rh_logfile);

			if (do_logrotate) signal(SIGHUP, logrotate_on_signal);
		}
	}
	else svlogfd = -1;

	/* Unix socket bind only. */
	if (rh_unixsock_path) goto _usinit;

	/* Admin requested operating only on V4 socket. */
	if (ipv4_only == YES) goto _v4init;

	/* IPv6 socket init */
	sv6fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (sv6fd == -1) goto _v4init; /* ok no v6, fallback to v4 */
	c = 1;
	if (setsockopt(sv6fd, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(c)) == -1)
		rh_perror("error setting SO_REUSEADDR ipv6 socket option");
#if defined(SOL_IPV6) && defined(IPV6_V6ONLY)
	c = 1;
	if (setsockopt(sv6fd, SOL_IPV6, IPV6_V6ONLY, &c, sizeof(c)) == -1)
		rh_perror("error setting IPV6_V6ONLY ipv6 socket option");
#endif

	rh_memzero(&sv6addr, sizeof(sv6addr));
	sv6addr.sin6_family = AF_INET6;
	if (rh_bindaddr6_s) {
		if (inet_pton(AF_INET6, rh_bindaddr6_s, &sv6addr.sin6_addr) < 0)
			xexits("%s: invalid ipv6 bind address was specified!", rh_bindaddr6_s);
	}
	else sv6addr.sin6_addr = in6addr_any;
	sv6addr.sin6_port = htons(rh_str_int(rh_port_s, &stoi));
	if (!str_empty(stoi)) xexits("%s: invalid port number", rh_port_s);

	if (bind(sv6fd, (struct sockaddr *)&sv6addr, sizeof(sv6addr)) == -1) {
		rh_perror("ipv6 binding error");
		close(sv6fd);
		sv6fd = -1;
		goto _v4init;
	}

	if (listen(sv6fd, 128) == -1) {
		rh_perror("ipv6 listening error");
		close(sv6fd);
		sv6fd = -1;
		goto _v4init;
	}

_v4init:
	/* IPv4 socket init */
	sv4fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sv4fd == -1) xerror("error creating socket");
	c = 1;
	if (setsockopt(sv4fd, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(c)) == -1)
		rh_perror("error setting SO_REUSEADDR socket option");

	rh_memzero(&sv4addr, sizeof(sv4addr));
	sv4addr.sin_family = AF_INET;
	if (rh_bindaddr4_s) {
		if (inet_pton(AF_INET, rh_bindaddr4_s, &sv4addr.sin_addr) < 0)
			xexits("%s: invalid bind address was specified!", rh_bindaddr4_s);
	}
	else sv4addr.sin_addr.s_addr = INADDR_ANY;
	sv4addr.sin_port = htons(rh_str_int(rh_port_s, &stoi));
	if (!str_empty(stoi)) xexits("%s: invalid port number", rh_port_s);

	if (bind(sv4fd, (struct sockaddr *)&sv4addr, sizeof(sv4addr)) == -1)
		xerror("binding error");

	if (listen(sv4fd, 128) == -1)
		xerror("listening error");

_usinit:
	if (!rh_unixsock_path) goto _initdone;
	/* Unix socket init */
	rh_memzero(&usaddr, sizeof(struct sockaddr_un));
	usaddr.sun_family = AF_UNIX;
	if (rh_unixsock_path[0] != '@') unlink(rh_unixsock_path);
	rh_strlcpy(usaddr.sun_path, rh_unixsock_path, sizeof(usaddr.sun_path));
	if (rh_unixsock_path[0] == '@') {
		usaddr.sun_path[0] = '\0';
		unl = sizeof(usaddr.sun_family) + strlen(rh_unixsock_path);
	}
	else unl = sizeof(struct sockaddr_un);

	usfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (usfd == -1) xerror("error creating unix socket");

	if (rh_unixsock_user && rh_unixsock_group) {
		uid_t uid;
		gid_t gid;

		uid = uidbyname(rh_unixsock_user);
		if (uid == NOUID) xexits("unix socket: user %s doesn't exist", rh_unixsock_user);
		gid = gidbyname(rh_unixsock_group);
		if (gid == NOGID) xexits("unix socket: group %s doesn't exist", rh_unixsock_group);

		if (fchown(usfd, uid, gid) == -1) xerror("unix socket chown failed");
	}
	if (rh_unixsock_mode) {
		mode_t mode;
		char *stoi;

		mode = (mode_t)strtoul(rh_unixsock_mode, &stoi, 8);
		if (!str_empty(stoi)) xexits("wrong socket file mode %s!", rh_unixsock_mode);

		if (fchmod(usfd, mode) == -1) xerror("unix socket chmod failed");
	}

	if (bind(usfd, (struct sockaddr *)&usaddr, unl) == -1)
		xerror("unix socket binding error");

	if (listen(usfd, 128) == -1)
		xerror("unix socket listening error");

_initdone:

	if (!no_daemonise) do_daemonise();
	svpid = getpid();

	if (!switch_user_on_fork) {
		void *usw;

		usw = init_user_switch(
			rh_switch_user, rh_switch_group,
			rh_switch_euser, rh_switch_egroup,
			rh_switch_groups);

		if (rh_chroot_dir) {
			if (chdir(rh_chroot_dir) == -1)
				xerror("changing root to \"%s\"", rh_chroot_dir);
			if (chroot(rh_chroot_dir) == -1)
				xerror("changing root to \"%s\"", rh_chroot_dir);
		}

		user_switch_setid_policy(usw, drop_setuid, drop_setgid);
		rh_issuper = user_switch_issuper(usw);
		apply_user_switch(usw);
		free_user_switch(usw);
	}

	while (1) {
		struct client_info *clinfo;
		int fdcnt = 0, fdgot, logpipe[2];
		pid_t pid;

		rh_memzero(&svfds, sizeof(svfds));
		for (fdcnt = 0; fdcnt < STAT_ARRAY_SZ(svfds); fdcnt++) svfds[fdcnt].fd = -1;
		fdcnt = 0;

		/* V4 server is required, so it's always there, unless there is a UNIX socket. */
		if (usfd == -1) {
			if (fdcnt > STAT_ARRAY_SZ(svfds)-1) goto _plerr;
			svfds[fdcnt].fd = sv4fd;
			svfds[fdcnt].events = POLLIN;
			fdcnt++;
		}
		else {
			if (fdcnt > STAT_ARRAY_SZ(svfds)-1) goto _plerr;
			svfds[fdcnt].fd = usfd;
			svfds[fdcnt].events = POLLIN;
			fdcnt++;
		}
		/* V6 server is optional. */
		if (sv6fd != -1) {
			if (fdcnt > STAT_ARRAY_SZ(svfds)-1) goto _plerr;
			svfds[fdcnt].fd = sv6fd;
			svfds[fdcnt].events = POLLIN;
			fdcnt++;
		}

		/* Prepare client info structure */
		clinfo = rh_malloc(sizeof(struct client_info));
		clinfo->ralimitup.total = ratelimit_up;
		clinfo->ralimitdown.total = ratelimit_down;

		/* Listening on multiple servers */
_plagain:	if (poll(svfds, fdcnt, -1) == -1) {
			if (errno == EINTR || errno == EAGAIN) goto _plagain;
_plerr:			xerror("polling listening fds");
		}

		fdgot = -1;
		for (fdcnt = 0; fdcnt < STAT_ARRAY_SZ(svfds); fdcnt++) {
			if (!(svfds[fdcnt].revents & POLLIN)) continue;
			fdgot = svfds[fdcnt].fd;
			break;
		}
		if (fdgot == -1) {
			rh_esay("no usable fd was returned by poll!");
			goto _drop_client;
		}

		/* Accepting new UNIX connection */
		if (usfd != -1 && usfd == fdgot) {
			socklen_t ucrl;

			/* Accepted UNIX connection - mark as such */
			clinfo->af = AF_UNIX;

			/* Preallocate things for accept call */
			clinfo->sockaddrlen = sizeof(struct sockaddr_un);
			clinfo->sockaddr = rh_malloc(sizeof(struct sockaddr_un));

			/* Fill server port number */
			clinfo->servport = rh_strdup(rh_unixsock_path);

			/* Accept connection fd */
			clinfo->clfd = accept(usfd,
				(struct sockaddr *)clinfo->sockaddr, &clinfo->sockaddrlen);
			if (clinfo->clfd == -1) {
				rh_perror("unix socket accepting error");
				goto _drop_client;
			}

			/* Resolve basic peer credentials */
			clinfo->ucr = rh_malloc(sizeof(struct ucred));
			ucrl = sizeof(struct ucred);
			if (getsockopt(clinfo->clfd, SOL_SOCKET, SO_PEERCRED, clinfo->ucr, &ucrl) == -1) {
				rh_perror("getting unix socket peer credentials error");
				goto _drop_client;
			}
		}
		/* Accepting new V4 connection */
		else if (sv4fd != -1 && sv4fd == fdgot) {
			/* Accepted V4 connection - mark as such */
			clinfo->af = AF_INET;

			/* Preallocate things for accept call */
			clinfo->sockaddrlen = sizeof(struct sockaddr_in);
			clinfo->sockaddr = rh_malloc(sizeof(struct sockaddr_in));

			/* Fill server port number */
			clinfo->servport = rh_strdup(rh_port_s);

			/* Accept connection fd */
			clinfo->clfd = accept(sv4fd,
				(struct sockaddr *)clinfo->sockaddr, &clinfo->sockaddrlen);
			if (clinfo->clfd == -1) {
				rh_perror("accepting error");
				goto _drop_client;
			}
		}
		/* Accepting new V6 connection */
		else if (sv6fd != -1 && sv6fd == fdgot) {
			/* Accepted V6 connection - mark as such */
			clinfo->af = AF_INET6;

			/* Preallocate things for accept call */
			clinfo->sockaddrlen = sizeof(struct sockaddr_in6);
			clinfo->sockaddr = rh_malloc(sizeof(struct sockaddr_in6));

			/* Fill server port number */
			clinfo->servport = rh_strdup(rh_port_s);

			/* Accept connection fd */
			clinfo->clfd = accept(sv6fd,
				(struct sockaddr *)clinfo->sockaddr, &clinfo->sockaddrlen);
			if (clinfo->clfd == -1) {
				rh_perror("ipv6 accepting error");
				goto _drop_client;
			}
		}
		else goto _drop_client;

		/* Trim unused memory */
		clinfo->sockaddr = rh_realloc(clinfo->sockaddr, clinfo->sockaddrlen);

		/* resolving numbers must be fast */
		if (!resolve_ip(&clinfo->ipaddr, clinfo)) {
			rh_esay("trouble resolving client address: %s", clinfo->ipaddr);
			goto _drop_client;
		}
		if (!resolve_port(&clinfo->port, clinfo)) {
			rh_esay("trouble resolving client port: %s", clinfo->port);
			goto _drop_client;
		}

		/* set socket timeouts */
		io_socket_timeout(clinfo->clfd, rh_client_receive_timeout, rh_client_send_timeout);

		/* too many of you - go away. */
		if (client_all_connections_limit > 0
		&& client_all_connections_limit >= client_connections_limit
		&& count_all_clients() >= client_all_connections_limit)
			goto _drop_client;
		if (client_connections_limit > 0
		&& count_clients(clinfo->ipaddr) >= client_connections_limit)
			goto _drop_client;

		if (svlogfd != -1) {
			rh_yesno notasock = NO;
			size_t maxlogsz;

			/*
			 * Unix signals considered harmful. They are not reliable,
			 * they can get lost if there are more than one and
			 * they're very limited, not portable and cannot be (re)defined.
			 * So there is unreliable yet working _portable_ solution:
			 * fill the pipe, then drain it when waited for child.
			 */
			if (socketpair(AF_UNIX, SOCK_STREAM, 0, logpipe) != 0) {
_dopipeinstead:			notasock = YES;
				if (pipe(logpipe) != 0) xerror("log pipe failed");
			}

			/*
			 * So if we're got a socket pair, then try to set the best
			 * buffer size for it so all the logs will fit nicely.
			 * And client will count the written bytes and exit prematurely
			 * if suddenly log data does not fit.
			 */
			if (!notasock) {
				maxlogsz = log_bufsize;
_trysswr:			if (setsockopt(logpipe[1], SOL_SOCKET, SO_SNDBUF,
					&maxlogsz, sizeof(maxlogsz)) == -1) {
					maxlogsz /= 2;
					if (maxlogsz < RH_ALLOC_MAX) {
						rh_perror("setting WR log pipe buffer size failed");
						close(logpipe[0]);
						close(logpipe[1]);
						goto _dopipeinstead;
					}
					goto _trysswr;
				}

				clinfo->maxlogsz = maxlogsz;

				maxlogsz = log_bufsize;
_tryssrd:			if (setsockopt(logpipe[0], SOL_SOCKET, SO_RCVBUF,
					&maxlogsz, sizeof(maxlogsz)) == -1) {
					maxlogsz /= 2;
					if (maxlogsz < RH_ALLOC_MAX) {
						rh_perror("setting RD log pipe buffer size failed");
						close(logpipe[0]);
						close(logpipe[1]);
						goto _dopipeinstead;
					}
					goto _tryssrd;
				}
			}
			else clinfo->maxlogsz = NOSIZE;

			/*
			 * if poor pipe will fill, then do not deadlock.
			 * Child will just spit out log line to stdout.
			 */
			rh_fcntl(logpipe[0], F_SETFL, O_NONBLOCK, YES);
			rh_fcntl(logpipe[1], F_SETFL, O_NONBLOCK, YES);
		}
		else clinfo->logfd = -1;

		/* The rest is protoindependent code, and client E.P. */
		pid = fork();
		if (pid == -1) {
			rh_perror("fork failed");
			goto _drop_client;
		}

		if (pid == 0) {
			if (sv4fd != -1) close(sv4fd);
			if (sv6fd != -1) close(sv6fd);
			if (usfd != -1) close(usfd);
			clinfo->pid = getpid();
			if (svlogfd != -1) {
				pfree(svlogln);
				clinfo->logfd = logpipe[1];
				if (svlogfd != 1) close(svlogfd);
				close(logpipe[0]);
			}

			if (switch_user_on_fork) {
				void *usw;

				usw = init_user_switch(
					rh_switch_user, rh_switch_group,
					rh_switch_euser, rh_switch_egroup,
					rh_switch_groups);

				if (rh_chroot_dir) {
					if (chdir(rh_chroot_dir) == -1)
						xerror("changing root to \"%s\"", rh_chroot_dir);
					if (chroot(rh_chroot_dir) == -1)
						xerror("changing root to \"%s\"", rh_chroot_dir);
				}

				user_switch_setid_policy(usw, drop_setuid, drop_setgid);
				rh_issuper = user_switch_issuper(usw);
				apply_user_switch(usw);
				free_user_switch(usw);
			}

			/* Run the main client code */
			run_client(clinfo);
			rh_exit(0);
		}
		else {
			if (svlogfd != -1) {
				close(logpipe[1]);
				add_client(pid, logpipe[0], clinfo->ipaddr);
			}
			else add_client(pid, -1, clinfo->ipaddr);

_drop_client:		pfree(clinfo->sockaddr);
			pfree(clinfo->ipaddr);
			pfree(clinfo->port);
			pfree(clinfo->servport);
			close(clinfo->clfd);
			pfree(clinfo);
		}
	}

	rh_exit(0);
	return 0;
}
