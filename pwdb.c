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

#define NOUID ((uid_t)-1)
#define NOGID ((gid_t)-1)

uid_t uidbyname(const char *name)
{
	struct passwd *p;

	if (is_number(name, NO))
		return (uid_t)atoi(name);
	p = getpwnam(name);
	if (p) return p->pw_uid;
	else xexits("%s: user was not found", name);
	return NOUID;
}

gid_t gidbyuid(uid_t uid)
{
	struct passwd *p;

	p = getpwuid(uid);
	if (p) return p->pw_gid;
	return (gid_t)uid;
}

gid_t gidbyname(const char *name)
{
	struct group *g;

	if (is_number(name, NO))
		return (gid_t)atoi(name);
	g = getgrnam(name);
	if (g) return g->gr_gid;
	else xexits("%s: group was not found", name);
	return NOGID;
}

int getugroups(const char *name, gid_t gr, gid_t *grps, int *ngrps)
{
	if (is_number(name, NO)) {
		struct passwd *p;
		p = getpwuid(atoi(name));
		if (p) name = p->pw_name;
	}
	return getgrouplist(name, gr, grps, ngrps);
}

char *namebyuid(uid_t uid)
{
	struct passwd *p;
	char *r = NULL;

	p = getpwuid(uid);
	if (p) return rh_strdup(p->pw_name);
	else {
		rh_asprintf(&r, "%u", uid);
		shrink_dynstr(&r);
		return r;
	}
}

char *namebygid(gid_t gid)
{
	struct group *g;

	g = getgrgid(gid);
	if (g) return rh_strdup(g->gr_name);
	else {
		char *r = NULL;
		rh_asprintf(&r, "%u", gid);
		shrink_dynstr(&r);
		return r;
	}
}

struct user_switch {
	rh_yesno switch_usr;
	rh_yesno switch_grp;
	rh_yesno switch_grps;

	uid_t targ_uid, targ_euid;
	gid_t targ_gid, targ_egid;
	gid_t *targ_gids;
	int targ_gids_sz;
};

void *init_user_switch(
	const char *user, const char *group,
	const char *euser, const char *egroup,
	const char *groups)
{
	char *s, *d, *t, *T;
	struct user_switch *r;
	gid_t tgid;

	r = rh_malloc(sizeof(struct user_switch));

	r->switch_usr = r->switch_grp = r->switch_grps = NO;
	r->targ_uid = getuid();
	r->targ_euid = geteuid();
	r->targ_gid = getgid();
	r->targ_egid = getegid();
	r->targ_gids_sz = getgroups(0, NULL);
	if (r->targ_gids_sz == -1) r->targ_gids_sz = RH_ALLOC_SMALL;
	r->targ_gids = rh_malloc(r->targ_gids_sz * sizeof(gid_t));
	r->targ_gids_sz = getgroups(r->targ_gids_sz, r->targ_gids);

	if (user) {
		r->switch_usr = YES;
		r->switch_grp = YES;
		r->switch_grps = YES;
		r->targ_uid = uidbyname(user);
	}

	if (group) {
		r->switch_grp = YES;
		r->targ_gid = gidbyname(group);
	}
	else r->targ_gid = gidbyuid(r->targ_uid);

	if (euser) {
		r->switch_usr = YES;
		r->targ_euid = uidbyname(euser);
	}
	else r->targ_euid = r->targ_uid; /* no implicit setuid */

	if (egroup) {
		r->switch_grp = YES;
		r->targ_egid = gidbyname(egroup);
	}
	else r->targ_egid = r->targ_gid; /* no implicit setgid */

	if (groups) {
		r->switch_grps = YES;

		r->targ_gids_sz = 0;
		pfree(r->targ_gids);

		T = rh_strdup(groups);
		s = d = T; t = NULL;
		while ((s = strtok_r(d, ":", &t))) {
			if (d) d = NULL;

			tgid = gidbyname(s);
			r->targ_gids = rh_realloc(r->targ_gids,
				(r->targ_gids_sz+1) * sizeof(gid_t));
			r->targ_gids[r->targ_gids_sz] = tgid;
			r->targ_gids_sz++;
		}

		pfree(T);
	}
	else if (user) {
		r->targ_gids = rh_malloc(sizeof(gid_t));
		r->targ_gids_sz = 1;
		if (getugroups(user, r->targ_gid, r->targ_gids, &r->targ_gids_sz) == -1) {
			r->targ_gids = rh_realloc(r->targ_gids, r->targ_gids_sz * sizeof(gid_t));
				if (getugroups(user, r->targ_gid,
					r->targ_gids, &r->targ_gids_sz) == -1)
						xexits("%s", user);
		}
	}

	return (void *)r;
}

void user_switch_setid_policy(void *uswitch, rh_yesno nosetuid, rh_yesno nosetgid)
{
	struct user_switch *usw = uswitch;

	if (nosetuid == YES) {
		usw->switch_usr = YES;
		usw->targ_euid = usw->targ_uid;
	}
	if (nosetgid == YES) {
		usw->switch_grp = YES;
		usw->targ_egid = usw->targ_gid;
	}
}

void apply_user_switch(const void *uswitch)
{
	const struct user_switch *usw = uswitch;

	if (usw->switch_grps == YES
		&& setgroups(usw->targ_gids_sz, usw->targ_gids) == -1) xerror("setgroups");
	if (usw->switch_grp == YES
		&& setregid(usw->targ_gid, usw->targ_egid) == -1) xerror("setregid");
	if (usw->switch_usr == YES
		&& setreuid(usw->targ_uid, usw->targ_euid) == -1) xerror("setreuid");
}

rh_yesno user_switch_issuper(const void *uswitch)
{
	const struct user_switch *usw = uswitch;

	return (usw->targ_euid == 0 || usw->targ_uid == 0);
}

void free_user_switch(void *uswitch)
{
	struct user_switch *usw = uswitch;

	pfree(usw->targ_gids);
	pfree(usw);
}
