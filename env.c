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

void clear_environ(void)
{
	char **env = environ;

	while (*env) {
		*env = NULL;
		env++;
	}
	*environ = NULL;
}

void preset_fsa(struct fmtstr_args **fsa, size_t *nr_fsa, const struct client_state *clstate)
{
	struct client_info *clinfo = clstate->clinfo;
	char *s;
	struct fmtstr_args *tfsa = NULL;
	size_t nr_tfsa = 0;

	APPEND_FSA(tfsa, nr_tfsa, "progname", 0, "%s", progname);
	APPEND_FSA(tfsa, nr_tfsa, "bindaddr4", 0, "%s", rh_bindaddr4_s);
	APPEND_FSA(tfsa, nr_tfsa, "bindaddr6", 0, "%s", rh_bindaddr6_s);
	APPEND_FSA(tfsa, nr_tfsa, "bindport", 0, "%s", rh_port_s);
#ifdef WITH_TLS
	APPEND_FSA(tfsa, nr_tfsa, "bindtlsport", 0, "%s", rh_tlsport_s);
#endif
	APPEND_FSA(tfsa, nr_tfsa, "httpident", 0, "%s", rh_ident);
	APPEND_FSA(tfsa, nr_tfsa, "httproot", 0, "%s", rh_root_dir);
	APPEND_FSA(tfsa, nr_tfsa, "logfile", 0, "%s", rh_logfile);
	APPEND_FSA(tfsa, nr_tfsa, "switch_user", 0, "%s", rh_chroot_dir);
	APPEND_FSA(tfsa, nr_tfsa, "switch_user", 0, "%s", rh_switch_user);
	APPEND_FSA(tfsa, nr_tfsa, "switch_euser", 0, "%s", rh_switch_euser);
	APPEND_FSA(tfsa, nr_tfsa, "switch_group", 0, "%s", rh_switch_group);
	APPEND_FSA(tfsa, nr_tfsa, "switch_egroup", 0, "%s", rh_switch_egroup);
	APPEND_FSA(tfsa, nr_tfsa, "switch_groups", 0, "%s", rh_switch_groups);

	APPEND_FSA(tfsa, nr_tfsa, "pid", sizeof(pid_t), "%u", &clinfo->pid);
	APPEND_FSA(tfsa, nr_tfsa, "clinfo_fd", sizeof(int), "%u", &clinfo->clfd);
	switch (clinfo->af) {
		case AF_INET: s = "IPv4"; break;
		case AF_INET6: s = "IPv6"; break;
		default: s = ""; break;
	}
	APPEND_FSA(tfsa, nr_tfsa, "clinfo_af", 0, "%s", s);
	APPEND_FSA(tfsa, nr_tfsa, "clinfo_ipaddr", 0, "%s", clinfo->ipaddr); /* always real one */
	APPEND_FSA(tfsa, nr_tfsa, "clinfo_port", 0, "%s", clinfo->port);
	APPEND_FSA(tfsa, nr_tfsa, "client_ipaddr", 0, "%s", clstate->ipaddr); /* <-- use this */
#ifdef WITH_TLS
	APPEND_FSA(tfsa, nr_tfsa, "client_proto", 0, "%s", clinfo->cltls ? "https" : "http");
#else
	APPEND_FSA(tfsa, nr_tfsa, "client_proto", 0, "%s", "http");
#endif

	APPEND_FSA(tfsa, nr_tfsa, "req_time", 0, "%s", clstate->request_date);
	APPEND_FSA(tfsa, nr_tfsa, "req_keepalive", 0, "%s",
		clstate->is_keepalive == YES ? "yes" : "no");
	switch (clstate->method) {
		case REQ_METHOD_GET: s = "GET"; break;
		case REQ_METHOD_HEAD: s = "HEAD"; break;
		case REQ_METHOD_POST: s = "POST"; break;
		default: s = ""; break;
	}
	APPEND_FSA(tfsa, nr_tfsa, "req_number", sizeof(size_t), "%zu", &clstate->nr_requests);
	APPEND_FSA(tfsa, nr_tfsa, "req_method", 0, "%s", s);
	APPEND_FSA(tfsa, nr_tfsa, "req_line", 0, "%s",
		clstate->request_lines ? clstate->request_lines[0] : "<empty>");
	APPEND_FSA(tfsa, nr_tfsa, "req_request", 0, "%s",
		clstate->request ? clstate->request : "<empty>");
	APPEND_FSA(tfsa, nr_tfsa, "req_proto_version", 0, "%s",
		clstate->protoversion ? clstate->protoversion : "0.9");
	APPEND_FSA(tfsa, nr_tfsa, "req_path", 0, "%s",
		clstate->path ? clstate->path : "<empty>");
	APPEND_FSA(tfsa, nr_tfsa, "req_realpath", 0, "%s",
		clstate->realpath ? clstate->realpath : "<empty>");
	switch (clstate->filedir) {
		case PATH_IS_FILE:
			if (clstate->is_exec) s = "X";
			else if (clstate->is_rsrc) s = "R";
			else s = "F"; break;
		case PATH_IS_DIR: s = "D"; break;
		default: s = ""; break;
	}
	APPEND_FSA(tfsa, nr_tfsa, "req_filedir", 0, "%s", s);
	APPEND_FSA(tfsa, nr_tfsa, "req_args", 0, "%s", clstate->strargs);
	APPEND_FSA(tfsa, nr_tfsa, "req_filesize", sizeof(rh_fsize), "%llu", &clstate->filesize);
	APPEND_FSA(tfsa, nr_tfsa, "req_range_start",
		sizeof(rh_fsize), "%llu", &clstate->range_start);
	APPEND_FSA(tfsa, nr_tfsa, "req_range_end", sizeof(rh_fsize), "%llu", &clstate->range_end);
	APPEND_FSA(tfsa, nr_tfsa, "req_recv", sizeof(rh_fsize), "%llu", &clstate->recvbytes);
	APPEND_FSA(tfsa, nr_tfsa, "req_sent", sizeof(rh_fsize), "%llu", &clstate->sentbytes);
	switch (clstate->iostate) {
		case IOS_ALL_OK: s = "IOK"; break;
		case IOS_READ_ERROR: s = "RERR"; break;
		case IOS_WRITE_ERROR: s = "WERR"; break;
		case IOS_SEEK_ERROR: s = "SERR"; break;
		default: s = ""; break;
	}
	APPEND_FSA(tfsa, nr_tfsa, "req_iostate", 0, "%s", s);
	APPEND_FSA(tfsa, nr_tfsa, "req_ioerror", 0, "%s", rh_strerror(clstate->ioerror));
	APPEND_FSA(tfsa, nr_tfsa, "req_status", 0, "%s",
		clstate->status ? clstate->status : "494");

	*nr_fsa = nr_tfsa;
	*fsa = tfsa;
}
