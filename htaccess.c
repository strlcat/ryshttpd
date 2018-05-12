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

#define retn(x) do { pfree(s); return x; } while (0)
rh_yesno is_htaccess(const char *path)
{
	char *s, *d;

	s = rh_strdup(path);
	d = basename(s);
	if (strstr(d, rh_htaccess_name)) retn(YES);

	retn(NO);
}
#undef retn

static char *rewrite_resolve_substs(const void *rgx, const char *src, const char *rwr)
{
	char *s, *d, *t;
	char T[8];
	size_t n, rsz, idx;
	char *r;

	r = rh_strdup(rwr);
	rsz = rh_szalloc(r);
	if (rsz < RH_ALLOC_MAX) {
		rsz = RH_ALLOC_MAX;
		r = rh_realloc(r, rsz);
	}
	if (!is_fmtstr(rwr)) return r;

	s = d = r;
	while (1) {
		s = strstr(d, "%{");
		if (!s) break;
		t = d = s+CSTR_SZ("%{");
		while (1) {
			if (!isdigit(*d)) break;
			d++;
		}
		if (t == d || *d != '}') continue;

		rh_strlcpy_real(T, t, d-t+1 > sizeof(T) ? sizeof(T) : d-t+1);
		idx = rh_str_size(T, &t);
		if (!str_empty(t)) continue;

		t = regex_get_match(rgx, src, idx);

		d += CSTR_SZ("}");
		rh_strlcpy_real(T, s, d-s+1 > sizeof(T) ? sizeof(T) : d-s+1);
		n = rh_strlrep(r, rsz, T, t);
		d = s + (t ? strlen(t) : 0);
		pfree(t);
	}

	return r;
}

static int htaccess_single(struct client_state *clstate, const char *htadir, const char *path)
{
	void *cfg;
	char *ln, *s, *d, *t, *p;
	size_t lnsz;
	struct netaddr net, addr;
	struct fmtstr_args *fsa;
	size_t nr_fsa;
	struct fmtstr_state fst;
	rh_yesno denied;
	int r;

	s = NULL;
	rh_asprintf(&s, "%s/%s", htadir, rh_htaccess_name);
	if (file_or_dir(s) != PATH_IS_FILE) {
		pfree(s);
		return 0;
	}

	if (rh_insecure_htaccess == NO) if (rh_issuper == NO && is_writable(s)) {
		pfree(s);
		return 0;
	}

	r = open(s, O_RDONLY);
	if (r == -1) {
		pfree(s);
		return 0;
	}
	pfree(s);

	cfg = load_config(r);
	if (!cfg) {
		close(r);
		return 0;
	}
	close(r);

	denied = NO; ln = NULL;
	while (1) {
		s = get_config_line(cfg);
		if (!s) break;

		lnsz = strlen(s);
		lnsz += RH_ALLOC_SMALL;
		if (lnsz < RH_ALLOC_MAX) lnsz = RH_ALLOC_MAX;
_rafmts:	ln = rh_realloc(ln, lnsz);
		rh_memzero(ln, lnsz);

		preset_fsa(&fsa, &nr_fsa, clstate);
		rh_memzero(&fst, sizeof(struct fmtstr_state));
		fst.args = fsa;
		fst.nargs = nr_fsa;
		fst.fmt = s;
		fst.result = ln;
		fst.result_sz = lnsz;
		parse_fmtstr(&fst);
		pfree(fsa);
		if (fst.trunc) {
			/*
			 * In some other places, e.g. logging, you may see
			 * there is actually no reallocation. It's intentional:
			 * because logs are somewhat limited in size, while
			 * here, there is no such cap (like pipe size).
			 * The only limit is to prevent insane reallocations.
			 * So I do reallocation attempts here.
			 */
			lnsz += RH_ALLOC_SMALL;
			if (lnsz > RH_XSALLOC_MAX) continue;
			goto _rafmts;
		}

_rahdrs:	if (headers_fmtstr_parse(clstate->headers, ln, lnsz, NULL) >= lnsz) {
			lnsz += RH_ALLOC_SMALL;
			if (lnsz > RH_XSALLOC_MAX) continue;
			ln = rh_realloc(ln, lnsz);
			goto _rahdrs;
		}
_raargs:	if (args_fmtstr_parse(clstate->args, ln, lnsz, NULL) >= lnsz) {
			lnsz += RH_ALLOC_SMALL;
			if (lnsz > RH_XSALLOC_MAX) continue;
			ln = rh_realloc(ln, lnsz);
			goto _raargs;
		}

		s = d = ln;

		d = strchr(s, ' ');
		if (!d) continue;
_trim:		*d = 0; d++;
		if (*d == ' ') goto _trim;

		if (!strcasecmp(s, "done")) {
			goto _xdone;
		}

		else if (!strcasecmp(s, "return")) {
_return:		r = rh_str_int(d, &t);
			if (!str_empty(t)) continue;
			goto _done;
		}

		else if (!strcasecmp(s, "header")) {
_header:		t = strchr(d, ' ');
			if (!t) goto _sethdr;
			*t = 0; t++;
_sethdr:		add_header(&clstate->sendheaders, d, t);

			continue;
		}

		else if (!strcasecmp(s, "redirect")) {
_redirect:		add_header(&clstate->sendheaders, "Location", d);
			r = 302;
			goto _done;
		}

		else if (!strcasecmp(s, "movedto")) {
_movedto:		add_header(&clstate->sendheaders, "Location", d);
			r = 301;
			goto _done;
		}

		else if (!strcasecmp(s, "deny")) {
_deny:			if (!strcasecmp(d, "all")) {
				denied = YES;
				continue;
			}

			if (rh_parse_addr(d, &net) == NO) continue;
			if (rh_parse_addr(clstate->ipaddr, &addr) == NO) continue;
			if (rh_match_addr(&net, &addr) == YES) denied = YES;

			continue;
		}

		else if (!strcasecmp(s, "allow")) {
_allow:			if (!strcasecmp(d, "all")) {
				denied = NO;
				continue;
			}

			if (rh_parse_addr(d, &net) == NO) continue;
			if (rh_parse_addr(clstate->ipaddr, &addr) == NO) continue;
			if (rh_match_addr(&net, &addr) == YES) denied = NO;

			continue;
		}

		else if (!strcasecmp(s, "noindex")) {
_noindex:		if (!strcasecmp(d, "yes") && !strcmp(htadir, path))
				clstate->noindex = YES;
			else clstate->noindex = NO;
			continue;
		}

		else if (!strcasecmp(s, "hideindex")) {
_hideindex:		if (clstate->hideindex_rgx) {
				t = regex_get_pattern(clstate->hideindex_rgx);
				regex_free(clstate->hideindex_rgx);
			}
			else t = NULL;
			if (!strcasecmp(d, "none")) {
				pfree(t);
				clstate->hideindex_rgx = NULL;
				continue;
			}
			if (t) rh_astrcat(&t, "|");
			rh_astrcat(&t, d);
			clstate->hideindex_rgx = regex_compile(t, NO, NO);
			pfree(t);
			if (regex_is_error(clstate->hideindex_rgx)) {
				rh_esay("%s/%s hideindex: regex error %s",
					htadir, rh_htaccess_name,
					regex_error(clstate->hideindex_rgx));
				regex_free(clstate->hideindex_rgx);
				clstate->hideindex_rgx = NULL;
			}
			continue;
		}

		else if (!strcasecmp(s, "ratelimit")) {
_ratelimit:		clstate->clinfo->ralimitup.total = rh_str_human_fsize(d, &t);
			if (!str_empty(t)) clstate->clinfo->ralimitup.total = NOFSIZE;
			clstate->clinfo->ralimitdown.total = clstate->clinfo->ralimitup.total;
			clstate->clinfo->ralimitup.calculated = clstate->clinfo->ralimitdown.calculated = NO;
			continue;
		}

		else if (!strcasecmp(s, "ratelimit_up")) {
_ratelimit_up:		clstate->clinfo->ralimitup.total = rh_str_human_fsize(d, &t);
			if (!str_empty(t)) clstate->clinfo->ralimitup.total = NOFSIZE;
			clstate->clinfo->ralimitup.calculated = NO;
			continue;
		}

		else if (!strcasecmp(s, "ratelimit_down")) {
_ratelimit_down:	clstate->clinfo->ralimitdown.total = rh_str_human_fsize(d, &t);
			if (!str_empty(t)) clstate->clinfo->ralimitdown.total = NOFSIZE;
			clstate->clinfo->ralimitdown.calculated = NO;
			continue;
		}

		else if (!strcasecmp(s, "matchip")) {
			char *dpath;

_matchip:		t = strchr(d, ' ');
			if (!t) continue;
			*t = 0; t++;

			unquote(d, strlen(d)+1);
			if (!strcasecmp(d, "any")) goto _do_matchip;

			if (rh_parse_addr(d, &net) == NO) continue;
			if (rh_parse_addr(clstate->ipaddr, &addr) == NO) continue;
			if (rh_match_addr(&net, &addr) == NO) continue;

_do_matchip:		dpath = rh_strdup(t);
			unquote(dpath, rh_szalloc(dpath));

			if (!strncmp(dpath, "matchip ", CSTR_SZ("matchip "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("matchip ");
				*(d-1) = 0;
				goto _matchip;
			}
			else if (!strcmp(dpath, "done")) {
				goto _xdone;
			}
			else if (!strncmp(dpath, "return ", CSTR_SZ("return "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("return ");
				*(d-1) = 0;
				goto _return;
			}
			else if (!strncmp(dpath, "header ", CSTR_SZ("header "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("header ");
				*(d-1) = 0;
				goto _header;
			}
			else if (!strncmp(dpath, "redirect ", CSTR_SZ("redirect "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("redirect ");
				*(d-1) = 0;
				goto _redirect;
			}
			else if (!strncmp(dpath, "movedto ", CSTR_SZ("movedto "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("movedto ");
				*(d-1) = 0;
				goto _movedto;
			}
			else if (!strncmp(dpath, "deny ", CSTR_SZ("deny "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("deny ");
				*(d-1) = 0;
				goto _deny;
			}
			else if (!strncmp(dpath, "allow ", CSTR_SZ("allow "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("allow ");
				*(d-1) = 0;
				goto _allow;
			}
			else if (!strncmp(dpath, "noindex ", CSTR_SZ("noindex "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("noindex ");
				*(d-1) = 0;
				goto _noindex;
			}
			else if (!strncmp(dpath, "hideindex ", CSTR_SZ("hideindex "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("hideindex ");
				*(d-1) = 0;
				goto _hideindex;
			}
			else if (!strncmp(dpath, "ratelimit ", CSTR_SZ("ratelimit "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("ratelimit ");
				*(d-1) = 0;
				goto _ratelimit;
			}
			else if (!strncmp(dpath, "ratelimit_up ", CSTR_SZ("ratelimit_up "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("ratelimit_up ");
				*(d-1) = 0;
				goto _ratelimit_up;
			}
			else if (!strncmp(dpath, "ratelimit_down ", CSTR_SZ("ratelimit_down "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("ratelimit_down ");
				*(d-1) = 0;
				goto _ratelimit_down;
			}
			else if (!strncmp(dpath, "rewrite ", CSTR_SZ("rewrite "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("rewrite ");
				*(d-1) = 0;
				goto _rewrite;
			}
			else if (!strncmp(dpath, "rematch ", CSTR_SZ("rematch "))) {
				pfree(ln);
				ln = dpath;
				s = dpath;
				d = dpath+CSTR_SZ("rematch ");
				*(d-1) = 0;
				goto _rewrite;
			}
			else {
				pfree(dpath);
				continue;
			}
		}

		else if (!strcasecmp(s, "rewrite")
		|| !strcasecmp(s, "rematch")) {
			rh_yesno do_single_rwr;
			void *rgx;
			char *ss, *dd, *tt, *dpath, *pat, *rwr;
			size_t dpathsz;
			rh_yesno f, F;
			size_t l;

_rewrite:		/*
			 * WARNING! The rewrite stuff is hacky -- expect bugs, hangs and glitches.
			 * YOU HAVE BEEN WARNED.
			 */

			if (!strcasecmp(s, "rewrite")) do_single_rwr = YES;
			else do_single_rwr = NO;

			/* single rewrite rule was processed already before */
			if (do_single_rwr == YES && clstate->was_rewritten == YES) continue;

			/* d == what */
			t = strchr(d, ' ');
			if (!t) continue;
			*t = 0; t++;

			/*
			 * t == pattern+rewriter mix
			 * this code was taken from super, parse_cmdline@cmdline.c.
			 */
			l = strlen(t);
			pat = rwr = NULL; ss = dd = t; f = F = NO;
			while (1) {
				if (*dd == '\"' && ((dd-t == 0) || (dd-t && *(dd-1) != '\\'))) {
					memmove(dd, dd+1, l-(dd-t)); l--;
					FLIP_YESNO(f);
					continue;
				}
				if (F
				|| (*dd == ' '
				&& ((dd-t == 0)
				|| (dd-t && *(dd-1) != '\\'))
				&& f == NO)) {
					*dd = 0;
					rh_strlrep(ss, l, "\\ ", " ");
					rh_strlrep(ss, l, "\\\"", "\"");
					if (!pat) pat = ss;
					else if (pat && !rwr) rwr = ss;
					else break;
					ss = dd+1;
				}
				if (F) break;
				dd++; if (str_empty(dd)) F = YES;
			}
			/* pat == pattern, rwr == rewriter */
			if (!pat || !rwr) continue;

			/* choose by whom to match */
			ss = dd = d; tt = dpath = NULL;
			while ((ss = strtok_r(dd, ",", &tt))) {
				if (dd) dd = NULL;

				if (!strcmp(ss, "client_ipaddr"))
					rh_astrcat(&dpath, clstate->ipaddr);
				else if (!strcmp(ss, "clinfo_ipaddr"))
					rh_astrcat(&dpath, clstate->clinfo->ipaddr);
				else if (!strcmp(ss, "clinfo_port"))
					rh_astrcat(&dpath, clstate->clinfo->port);
				else if (!strcmp(ss, "clinfo_servport"))
					rh_astrcat(&dpath, clstate->clinfo->servport);
				else if (!strcmp(ss, "clinfo_af")) {
					switch (clstate->clinfo->af) {
						case AF_INET: rh_astrcat(&dpath, "IPv4"); break;
						case AF_INET6: rh_astrcat(&dpath, "IPv6"); break;
						default: goto _addit; break;
					}
				}
				else if (!strcmp(ss, "clinfo_proto")) {
#ifdef WITH_TLS
					if (clstate->clinfo->cltls)
						rh_astrcat(&dpath, "https");
					else
#endif
					rh_astrcat(&dpath, "http");
				}
				else if (!strcmp(ss, "req_method")) {
					switch (clstate->method) {
						case REQ_METHOD_GET: rh_astrcat(&dpath, "GET"); break;
						case REQ_METHOD_HEAD: rh_astrcat(&dpath, "HEAD"); break;
						case REQ_METHOD_POST: rh_astrcat(&dpath, "POST"); break;
						default: goto _addit; break;
					}
				}
				else if (!strcmp(ss, "req_keepalive"))
					rh_astrcat(&dpath, clstate->is_keepalive == YES ? "keepalive" : "close");
				else if (!strcmp(ss, "req_line") && clstate->request_lines[0])
					rh_astrcat(&dpath, clstate->request_lines[0]);
				else if (!strcmp(ss, "req_request") && clstate->request)
					rh_astrcat(&dpath, clstate->request);
				else if (!strcmp(ss, "req_proto_version") && clstate->protoversion)
					rh_astrcat(&dpath, clstate->protoversion);
				else if (!strcmp(ss, "req_path") && clstate->path)
					rh_astrcat(&dpath, clstate->path);
				else if (!strcmp(ss, "req_realpath") && clstate->realpath)
					rh_astrcat(&dpath, clstate->realpath);
				else if (!strcmp(ss, "req_args"))
					rh_astrcat(&dpath, clstate->strargs);
				else if (!strncmp(ss, "hdr_", CSTR_SZ("hdr_"))) {
					char *pp, *cpp, *pss;

					cpp = rh_strdup(ss);
					pss = ss;

					ss += CSTR_SZ("hdr_");
					pp = find_header_value(clstate->headers, ss);
					if (!pp) {
						rh_strrep(ss, "_", "-");
						pp = find_header_value(clstate->headers, ss);
						if (!pp) {
							ss = pss;
							memcpy(ss, cpp, rh_szalloc(cpp));
							pfree(cpp);
							goto _addit;
						}
					}

					rh_astrcat(&dpath, pp);
					pfree(cpp);
				}
				else if (!strncmp(ss, "arg_", CSTR_SZ("arg_"))) {
					char *pp, *pss;

					pss = ss;

					ss += CSTR_SZ("arg_");
					pp = find_header_value(clstate->headers, ss);
					if (!pp) {
						ss = pss;
						goto _addit;
					}

					rh_astrcat(&dpath, pp);
				}
				else {
_addit:					rh_astrcat(&dpath, ss);
				}
			}

			ss = dpath;

			rgx = regex_compile(pat, NO, is_fmtstr(rwr) ? YES : NO);
			if (regex_is_error(rgx)) {
				rh_esay("%s/%s rewrite: regex error %s",
					htadir, rh_htaccess_name, regex_error(rgx));
				pfree(dpath);
				regex_free(rgx);
				continue;
			}
			if (regex_exec(rgx, dpath) == YES) {
				dpath = rewrite_resolve_substs(rgx, ss, rwr);
				dpathsz = rh_szalloc(dpath);
				pfree(ss); /* was dpath */
				regex_free(rgx);

				if (!strncmp(dpath, "rewrite ", CSTR_SZ("rewrite "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("rewrite ");
					*(d-1) = 0;
					goto _rewrite;
				}
				else if (!strncmp(dpath, "rematch ", CSTR_SZ("rematch "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("rematch ");
					*(d-1) = 0;
					goto _rewrite;
				}
				else if (!strcmp(dpath, "done")) {
					goto _xdone;
				}
				else if (!strncmp(dpath, "return ", CSTR_SZ("return "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("return ");
					*(d-1) = 0;
					goto _return;
				}
				else if (!strncmp(dpath, "header ", CSTR_SZ("header "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("header ");
					*(d-1) = 0;
					goto _header;
				}
				else if (!strncmp(dpath, "redirect ", CSTR_SZ("redirect "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("redirect ");
					*(d-1) = 0;
					goto _redirect;
				}
				else if (!strncmp(dpath, "movedto ", CSTR_SZ("movedto "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("movedto ");
					*(d-1) = 0;
					goto _movedto;
				}
				else if (!strncmp(dpath, "deny ", CSTR_SZ("deny "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("deny ");
					*(d-1) = 0;
					goto _deny;
				}
				else if (!strncmp(dpath, "allow ", CSTR_SZ("allow "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("allow ");
					*(d-1) = 0;
					goto _allow;
				}
				else if (!strncmp(dpath, "noindex ", CSTR_SZ("noindex "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("noindex ");
					*(d-1) = 0;
					goto _noindex;
				}
				else if (!strncmp(dpath, "hideindex ", CSTR_SZ("hideindex "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("hideindex ");
					*(d-1) = 0;
					goto _hideindex;
				}
				else if (!strncmp(dpath, "ratelimit ", CSTR_SZ("ratelimit "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("ratelimit ");
					*(d-1) = 0;
					goto _ratelimit;
				}
				else if (!strncmp(dpath, "ratelimit_up ", CSTR_SZ("ratelimit_up "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("ratelimit_up ");
					*(d-1) = 0;
					goto _ratelimit_up;
				}
				else if (!strncmp(dpath, "ratelimit_down ", CSTR_SZ("ratelimit_down "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("ratelimit_down ");
					*(d-1) = 0;
					goto _ratelimit_down;
				}
				else if (!strncmp(dpath, "matchip ", CSTR_SZ("matchip "))) {
					pfree(ln);
					ln = dpath;
					s = dpath;
					d = dpath+CSTR_SZ("matchip ");
					*(d-1) = 0;
					goto _matchip;
				}

				p = strchr(dpath, '?');
				if (p) {
					*p = 0;
					p++;
				}

				/*
				 * It's NOT the clean way to reset the part
				 * of client state here; it may change in future.
				 */
				clstate->filedir = 0;
				clstate->is_exec = NO;
				clstate->is_rsrc = NO;
				clstate->is_indx = NO;
				clstate->cgi_mode = 0;
				pfree(clstate->path);
				clstate->path = rh_strdup(dpath);
				filter_dotdots(clstate->path, rh_szalloc(clstate->path));
				pfree(clstate->realpath);
				pfree(clstate->args);
				pfree(clstate->strargs);
				if (p) {
					clstate->strargs = rh_strdup(p);
					filter_dotdots(clstate->strargs,
						rh_szalloc(clstate->strargs));
					clstate->args = parse_args(clstate->strargs);
				}

				pfree(dpath);

				if (str_empty(clstate->path)) {
					r = 400;
					goto _done;
				}

				if (clstate->path[0] != '/') {
					r = 400;
					goto _done;
				}

				r = HTA_REWRITE;
				/* If single rule, then mark as such */
				if (do_single_rwr == YES) clstate->was_rewritten = YES;
				goto _done;
			}
			regex_free(rgx);
		}
	}

_xdone:	if (denied == YES) r = 403;
	else r = 0;

_done:	free_config(cfg);
	pfree(ln);
	return r;
}

#define retn(x) do { pfree(ds); pfree(dp); return x; } while (0)
int verify_htaccess(struct client_state *clstate, const char *path, const char *rootdir)
{
	char *dp, *ds;
	char *s, *d, *t;
	size_t x;
	int r;

	x = strlen(rootdir);
	if (strncmp(path, rootdir, x) != 0) return 403;

	r = htaccess_single(clstate, rootdir, path);
	if (r > 0) return r;

	ds = rh_strdup(rootdir);
	if (x == 1 && *rootdir == '/') x = 0;
	dp = rh_strdup(path+x);

	s = d = dp; t = NULL;
	while ((s = strtok_r(d, "/", &t))) {
		if (d) d = NULL;

		if (x == 0) x = 1;
		else rh_astrcat(&ds, "/");
		rh_astrcat(&ds, s);
		r = htaccess_single(clstate, ds, path);
		if (r > 0) retn(r);
	}

	retn(0);
}
#undef retn
