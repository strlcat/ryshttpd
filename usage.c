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

void usage(void)
{
	rh_say(PROGRAM_NAME " is an embedded HTTP server.");
	rh_say("usage: %s <-r httproot> "
		"[-4FV] [-U path[:mode[:uid:gid]]] [-R resdef] [-p port] [-l logfile] [-O OPTION,...]", progname);
	rh_say("\n");
	rh_say("  -r httproot: (mandatory) specify http root directory to serve files from");
	rh_say("  -p port: specify alternative port number to bind to");
	rh_say("  -4: use only IPv4, never try to use IPv6");
	rh_say("  -U path[:mode[:uid:gid]]: listen only on UNIX socket specified by path");
	rh_say("    Networking options like port number and bind address are completely ignored.");
	rh_say("    Optional socket configuration \"mode\" sets Unix octal socket file mode,");
	rh_say("      and if followed by \"uid\" and \"gid\", sets socket file ownership.");
	rh_say("      Note that some of these operations might require sufficient privilege.");
	rh_say("    If socket \"path\" starts with '@' char, then abstract socket will be created,");
	rh_say("      and \"mode\", \"uid\" and \"gid\" parameters will be ignored.");
	rh_say("  -F: do not daemonise, stay in foreground (to see error messages)");
	rh_say("  -l logfile: enable logging to logfile (default is to never log anything)\n"
		"    It accepts strftime format, so filename may include current date\n"
		"    \"-\" as logfile redirects log to stdout rather than file (use with -F)");
	rh_say("\n");
	rh_say("  -R resdef: load custom resource to be used (as error page for example):");
	rh_say("    The format of resdef: filepath:path:name:args:mimetype");
	rh_say("    filepath is physical path of file in filesystem to be loaded");
	rh_say("    path is arbitrary http root path, can be any or NULL");
	rh_say("    if path begins with \"<text>\", then a text after the prefix will be");
	rh_say("    copied into resource, and no file will be opened and read.");
	rh_say("    name is resource lookup name, for error pages it must be");
	rh_say("      of form of errorNNN.html, where NNN is HTTP error code.");
	rh_say("      name cannot be NULL - it must be always specified.");
	rh_say("    args is argument string on which resource may be shown too. Can be NULL");
	rh_say("    mimetype must be specified as a simple string and cannot be NULL.");
	rh_say("    NULL must be specified as \"<null>\", not as an empty specifier.");
	rh_say("  -O OPTION: specify advanced option (or comma separated list of options):");
	rh_say("    -O hostnames=rgx: set regex hostname(s). If client provides something\n"
		"      other than matched, or nothing, then 404 error is returned to him.");
	rh_say("    -O indexes=rgx: regex of index files to lookup in directories");
	rh_say("    -O bindto4=ip4addr: bind to this ipv4 address");
	rh_say("    -O bindto6=ip6addr: bind to this ipv6 address");
	rh_say("    -O ident=str: set Server: ident string");
#ifdef WITH_LIBMAGIC
	rh_say("    -O magicdb=path: load alternative libmagic mime database");
#endif
	rh_say("    -O chroot=dir: chroot into this directory");
	rh_say("    -O forkuser: server stays with current privileges, but client changes");
	rh_say("    -O user=uid/uname: set uid to specified user or uid");
	rh_say("    -O euser=uid/uname: set euid to specified user or uid");
	rh_say("    -O group=gid/gname: set gid to specified group or gid");
	rh_say("    -O egroup=gid/gname: set egid to specified group or gid");
	rh_say("    -O groups=grouplist: set groups to specified list of ':' delimited groups");
	rh_say("    -O drop_setid: drop setuid and setgid access privileges");
	rh_say("    -O drop_setuid: drop setuid access privilege");
	rh_say("    -O drop_setgid: drop setgid access privilege");
	rh_say("    -O logformat=fmt: set log lines format to this format (see env.c)");
	rh_say("    -O timeformat=fmt: set log timestamps to this strftime format");
	rh_say("    -O cgiexecs=pattern: set cgi filenames match pattern");
	rh_say("    -O nhcgiexecs=pattern: set No Headers cgi filenames match pattern");
	rh_say("    -O cgiehexecs=pattern: set cgi End Head filenames match pattern");
	rh_say("    -O cgipath=pathspec: provide this PATH envvar to any CGI exec'd script");
	rh_say("    -O cgiserver=script: always execute this script, never lookup files or directories;\n"
		"      The script is provided with translated path given by client as it's first argument.");
	rh_say("    -O cgimode=mode: set default CGI mode. Useful only for cgiserver now.\n"
		"      Valid values: regular, noheaders, noendhead.");
	rh_say("    -O xrealip=ipaddr: if ipaddr matches with real one of client, and client\n"
		"      provies X-Real-IP header, then IP address from X-Real-IP header is taken\n"
		"      as the \"real\" remote client address and gets logged as such");
	rh_say("    -O htaccess=filename: set alternative htaccess file name");
	rh_say("    -O logrotate: enable SIGHUP listening and log reopening");
	rh_say("    -O dir_prepend_path=str: prepend this string before all paths in directory\n"
		"      listings, resource pages etc., so proper links are forwarded through\n"
		"      url rewriting frontend proxies. If -O xrealip= is also set, then this address\n"
		"      has access to reassign this prepend string with it's own using X-Base-Path header.\n"
		"      Note that ending forward slash is required!");
#ifndef WITH_LIBMAGIC
	rh_say("    -O content_charset=str set Content-Type \"charset\" to this value for text files");
#endif
	rh_say("    -O list_date_format=str: set date and time format for directory lists");
	rh_say("    -O follow_symlinks: follow symlinks, even if they lead outside of http root");
	rh_say("    -O insecure_htaccess: do not check .htaccess files to be writable by process");
	rh_say("    -O regex_no_case: toggle regex case sensitivity globally");
	rh_say("    -O no_dirsort: turn off directory listing sorting");
	rh_say("    -O try_shell_exec: if CGI direct exec fails, try to run program through shell");
	rh_say("    -O secure_httproot: prevent ascend out of current HTTP root with htaccess\n"
		"      \"httproot\" command, locking it into current HTTP root directory.");
	rh_say("    -O allow_tar: allow tar directory downloading everywhere.");
	rh_say("      By default, it can be enabled only from htaccess files.");
	rh_say("      If enabled, disabling tar archiving in htaccess is still possible.");
	rh_say("    -O no_cache_headers: disable mandatory cache related headers");
	rh_say("    -O rdwr_bufsize=size: set read/write temporary client buffer size");
	rh_say("    -O log_bufsize=size: set log 'pipe' and server log buffer size");
	rh_say("    -O max_client_connections=int: set connection limit per one IP address");
	rh_say("    -O max_all_client_connections=int: set total connection limit that this httpd can serve");
	rh_say("    -O client_ipv6_subnet=int: limit connections per IPv6 subnet prefix");
	rh_say("    -O request_timeout=secs: first request timeout in seconds");
	rh_say("    -O receive_timeout=secs: receive timeout in seconds");
	rh_say("    -O send_timeout=secs: send timeout in seconds");
	rh_say("    -O keepalive_timeout=secs: keepalive connection timeout in seconds");
	rh_say("    -O keepalive_requests=int: maximum number of keepalive requests\n"
		"      after which connection is forcibly closed");
	rh_say("    -O ratelimit=size: limit download and upload network speed globally.\n"
		"      number may be a raw value or a human readable value without fraction.\n"
		"      Note that values higher than 10M may require increasing -O rdwr_bufsize,\n"
		"      because of drifting sleeping accuracy of higher number of chunks.");
	rh_say("    -O ratelimit_up=size: limit upload network speed only.");
	rh_say("    -O ratelimit_down=size: limit upload network speed only.");
	rh_say("    -O oom_timer=usecs: repeat allocation attempts after this number of useconds.");
	rh_say("    -O oom_max_attempts=int: fail after this number of unsuccessful allocation attempts.");
	rh_say("    -O on_fs_error=int: return this HTTP error code on a generic filesystem error.");
	rh_say("\n");
	rh_say("  -V: show version number and exit");
	rh_say("\n");
	rh_exit(1);
}

void show_version(void)
{
	rh_say("\n");
	rh_say(PROGRAM_NAME " is an embedded HTTP server.");
	rh_say("Version " _RH_VERSION);
	rh_say("\n");
	rh_say("Copyright (C) Andrey Rys. All rights reserved.");
	rh_say("This server is licensed under std. MIT license.");
	rh_say("For details, see COPYRIGHT file in source archive.");
	rh_say("\n");
	rh_exit(0);
}
