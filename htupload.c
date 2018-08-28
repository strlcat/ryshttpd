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

/*
 * This is a sample program which works as simple file uploader agent.
 * It does not spit out HTML forms or any other HTML content to user.
 * Heck, it even does not have a usable user interface. It's your task.
 * However it enables simple file uploads via HTTP POST and multipart form data.
 *
 * To make it work, you should place it somewhere where ryshttpd will recognise
 * it as an executable, configure it (place htupload.conf alongside with it):
 *
 *	# files will be placed into this directory
 *	upload_dir /tmp
 *	# maximum file size in bytes
 *	max_file_size 1048576
 *
 * , and provide a separate HTML web page with file input id set to "file".
 * On success, this program will just give a message specified at the end.
 * On any other failure (including file size limit exceed), it will exit prematurely.
 */

#define _GNU_SOURCE
#include "httpd.h"

#define HTUPLOAD_CONF "htupload.conf"
#define RDWR_BUFSIZE 4096

char *progname;

static char *upload_dir;
static char *upload_file_name;
static char *upload_file_path;
static char *logfile;
static char *success_page;
static char *success_message;
static char *allowed_filenames;
static void *allowed_filenames_rgx;
static char *forbidden_filenames;
static void *forbidden_filenames_rgx;
static char *rdwr_data;
static rh_yesno allow_overwrite = NO;

static char *content_type;
static char *content_length;
static rh_fsize max_file_size = NOFSIZE, resolved_file_size, file_written_already;
static char *boundary;
static size_t boundarylen;
static char *reqpacket;
static void *filehead;

useconds_t rh_oom_timer = 100000;
unsigned long rh_oom_max_attempts = 100;

rh_yesno str_empty(const char *str)
{
	if (!*str) return YES;
	return NO;
}

rh_fsize rh_str_fsize(const char *s, char **stoi)
{
	*stoi = NULL;
	return (rh_fsize)strtoull(s, stoi, 10);
}

int file_or_dir(const char *path)
{
	struct stat st;

	rh_memzero(&st, sizeof(struct stat));
	if (stat(path, &st) == -1) return -1;
	if (S_ISDIR(st.st_mode)) return PATH_IS_DIR;
	return PATH_IS_FILE;
}

size_t shrink_dynstr(char **s)
{
	size_t x;

	if (!s) return NOSIZE;
	if (!*s) return NOSIZE;
	if (str_empty(*s)) return 0;

	x = strnlen(*s, RH_XSALLOC_MAX)+1;
	*s = rh_realloc(*s, x);
	return x;
}

size_t rh_strlcpy(char *d, const char *s, size_t n)
{
	size_t x;

	x = rh_strlcpy_real(d, s, n);
	if (x >= n) xexits("rh_strlcpy complains that data is truncated.");
	return x;
}

void rh_astrcat(char **d, const char *s)
{
	size_t dn, sn, t;
	char *dd;

	if (!s || !d) return;
	if (!*d) {
		*d = rh_strdup(s);
		return;
	}

	dd = *d;
	sn = strnlen(s, RH_XSALLOC_MAX);
	dn = t = shrink_dynstr(&dd);
	if (t > 0) t--;
	dn += sn+1;
	dd = rh_realloc(dd, dn);
	rh_strlcpy(dd+t, s, sn+1);
	*d = dd;
}

static size_t BLK_LEN_ADJ(rh_fsize filelen, rh_fsize read_already, size_t blklen)
{
	if (filelen == NOFSIZE) return blklen;
	return ((filelen - read_already) >= blklen) ? blklen : (filelen - read_already);
}

static void do_success_page(void)
{
	int fd;
	size_t sz;

	fd = open(success_page, O_RDONLY);
	if (fd == -1) xerror("%s", success_page);
	while (1) {
		sz = io_read_data(fd, rdwr_data, RDWR_BUFSIZE, NO, NULL);
		if (sz == 0 || sz == NOSIZE) break;
		io_write_data(1, rdwr_data, sz, NO, NULL);
	}
	close(fd);
}

static void do_log(void)
{
	int fd;
	char *logline = NULL;
	char *s;
	size_t n;

	fd = open(logfile, O_CREAT|O_WRONLY|O_APPEND, 0600);
	if (fd == -1) xerror("%s", logfile);

	/* Address */
	s = getenv("REMOTE_ADDR");
	if (!s) xexits("No remote addr!");
	rh_astrcat(&logline, s);
	rh_astrcat(&logline, " ");

	/* Date */
	s = getenv("REQUEST_DATE");
	if (!s) xexits("No request date!");
	rh_astrcat(&logline, s);
	rh_astrcat(&logline, " ");

	/* File path */
	rh_astrcat(&logline, "\"");
	rh_astrcat(&logline, upload_file_path);
	rh_astrcat(&logline, "\"");
	rh_astrcat(&logline, " ");

	/* File size */
	s = rh_malloc(32);
	snprintf(s, 32, "%llu", resolved_file_size);
	rh_astrcat(&logline, s);
	pfree(s);

	n = shrink_dynstr(&logline);
	if (n > 0) logline[n-1] = '\n';

	io_write_data(fd, logline, n, NO, NULL);

	pfree(logline);
	close(fd);
}

int main(void)
{
	int fd;
	void *cfg;
	char *s, *d, *t, *p;
	size_t sz, x;

	set_progname("htupload");

	rdwr_data = rh_malloc(RDWR_BUFSIZE);

	fd = open(HTUPLOAD_CONF, O_RDONLY);
	if (fd == -1) xerror("%s", HTUPLOAD_CONF);
	cfg = load_config(fd);
	if (!cfg) xexits("Cannot load config data!");
	close(fd);

	while (1) {
		s = get_config_line(cfg);
		if (!s) break;

		d = strchr(s, ' ');
		if (!d) continue;
_trim:		*d = 0; d++;
		if (*d == ' ') goto _trim;

		if (!strcmp(s, "upload_dir")) {
			pfree(upload_dir);
			upload_dir = rh_strdup(d);
			continue;
		}

		if (!strcmp(s, "max_file_size")) {
			max_file_size = rh_str_fsize(d, &p);
			if (!str_empty(p)) xexits("%s: invalid max file size!", d);
			continue;
		}

		if (!strcmp(s, "allow_overwrite")) {
			FLIP_YESNO(allow_overwrite);
			continue;
		}

		if (!strcmp(s, "log")) {
			pfree(logfile);
			logfile = rh_strdup(d);
			continue;
		}

		if (!strcmp(s, "success_page")) {
			pfree(success_page);
			success_page = rh_strdup(d);
			continue;
		}

		if (!strcmp(s, "success_message")) {
			pfree(success_message);
			success_message = rh_strdup(d);
			continue;
		}

		if (!strcmp(s, "forbidden_filenames")) {
			pfree(forbidden_filenames);
			forbidden_filenames = rh_strdup(d);
			continue;
		}

		if (!strcmp(s, "allowed_filenames")) {
			pfree(allowed_filenames);
			allowed_filenames = rh_strdup(d);
			continue;
		}
	}

	if (!upload_dir) xexits("No upload directory was given!");
	free_config(cfg);

	s = getenv("CONTENT_LENGTH");
	if (!s) {
		if (success_page) do_success_page();
		else xexits("No content length!");
	}
	content_length = rh_strdup(s);
	resolved_file_size = rh_str_fsize(content_length, &s);
	if (!str_empty(s)) xexits("Content-Length: %s is not a number!", content_length);

	s = getenv("CONTENT_TYPE");
	if (!s) {
		if (success_page) do_success_page();
		else xexits("No content type!");
	}
	content_type = rh_strdup(s);

	s = strchr(content_type, ';');
	if (!s) xexits("No boundary!");
	*s = 0; s++;
	d = strchr(s, '=');
	if (!d) xexits("No boundary!");
	*d = 0; d++;
	boundary = rh_strdup(d);
	boundarylen = rh_szalloc(boundary)-1;
	if (boundarylen == NOSIZE) xexits("malformed boundary");

	sz = (size_t)read(0, rdwr_data, RDWR_BUFSIZE);
	if (sz == 0 || sz == NOSIZE) xexits("read was too small");

	s = rdwr_data;
	s += boundarylen + CSTR_SZ("\r\n");
	d = memmem(rdwr_data, rh_szalloc(rdwr_data), "\r\n\r\n", CSTR_SZ("\r\n\r\n"));
	if (!d || d < s
	|| d - rdwr_data < CSTR_SZ("\r\n\r\n"))
		xexits("malformed POST data");
	rh_memzero(d, CSTR_SZ("\r\n\r\n"));
	reqpacket = rh_strdup(s);
	d += CSTR_SZ("\r\n\r\n");

	resolved_file_size -= (d-rdwr_data); /* head packet */
	resolved_file_size -= CSTR_SZ("\r\n"); /* tail file ending \r\n */
	resolved_file_size -= CSTR_SZ("--"); /* tail boundary prefix '--' */
	resolved_file_size -= boundarylen; /* tail boundary */
	resolved_file_size -= CSTR_SZ("--"); /* tail boundary suffix '--' */
	resolved_file_size -= CSTR_SZ("\r\n"); /* tail boundary ending \r\n */
	if (max_file_size != NOSIZE
	&& resolved_file_size >= max_file_size) xexits("File size exceeded allowable limit");

	if (sz-(d-rdwr_data))
		filehead = rh_memdup(d, sz-(d-rdwr_data));

	if (filehead) {
		s = filehead;
		d = memmem(filehead, rh_szalloc(filehead), boundary, boundarylen);
		if (d) {
			d -= CSTR_SZ("\r\n");
			d -= CSTR_SZ("--");
			if (d <= s) xexits("malformed POST data");
			filehead = rh_realloc(filehead, d-s);
		}
	}

	if (forbidden_filenames) {
		forbidden_filenames_rgx = regex_compile(forbidden_filenames, YES, NO);
		if (regex_is_error(forbidden_filenames_rgx))
			regex_xexits(forbidden_filenames_rgx);
	}
	if (allowed_filenames) {
		allowed_filenames_rgx = regex_compile(allowed_filenames, YES, NO);
		if (regex_is_error(allowed_filenames_rgx))
			regex_xexits(allowed_filenames_rgx);
	}

	s = d = reqpacket; t = NULL;
	while ((s = strtok_r(d, "\r", &t))) {
		if (d) d = NULL;

		*s = 0; s++; /* remove leading \n */
		p = strchr(s, ':');
		if (!p) continue;
_trimw:		*p = 0; p++;
		if (*p == ' ') goto _trimw;

		if (!strcmp(s, "Content-Disposition")) {
			char *ss, *dd, *tt, *pp;
			rh_yesno found;

			ss = dd = p; tt = NULL; found = NO;
			while ((ss = strtok_r(dd, ";", &tt))) {
				if (dd) dd = NULL;

				*ss = 0; ss++; /* remove leading space */
				pp = strchr(ss, '=');
				if (!pp) continue;
				*pp = 0; pp++;

				if (!strcmp(ss, "name")
				&& !strcmp(pp, "\"file\"")) found = YES;
				if (!strcmp(ss, "filename")
				&& found) {
					char *flt;

					rh_strlrep(pp, strlen(pp)+1, "\"", NULL);
					flt = rh_strdup(pp);
					upload_file_name = rh_strdup(basename(flt));
					pfree(flt);

					rh_astrcat(&upload_file_path, upload_dir);
					rh_astrcat(&upload_file_path, "/");
					rh_astrcat(&upload_file_path, upload_file_name);
					goto _found_filename; /* nothing needed anymore */
				}
			}
			break;
		}
	}

_found_filename:
	if (!upload_file_path) xexits("POST packet does not contain file name");

	if (allow_overwrite == NO
	&& file_or_dir(upload_file_path) != -1) xexits("File exists!");

	if (forbidden_filenames_rgx) {
		if (allowed_filenames_rgx) {
			if (regex_exec(forbidden_filenames_rgx, upload_file_name) == YES
			&& regex_exec(allowed_filenames_rgx, upload_file_name) == NO)
				xexits("File name is forbidden to use!");
			regex_free(allowed_filenames_rgx);
		}
		else {
			if (regex_exec(forbidden_filenames_rgx, upload_file_name) == YES)
				xexits("File name is forbidden to use!");
			regex_free(forbidden_filenames_rgx);
		}
	}

	fd = creat(upload_file_path, 0666);
	if (fd == -1) xerror("%s", upload_file_path);

	if (filehead) {
		x = rh_szalloc(filehead);
		write(fd, filehead, x);
		file_written_already += x;
		pfree(filehead);
		if (file_written_already >= resolved_file_size) goto _donealready;
	}

	while (1) {
		x = BLK_LEN_ADJ(resolved_file_size, file_written_already, RDWR_BUFSIZE);
		sz = io_read_data(0, rdwr_data, x, NO, NULL);
		if (sz == 0 || sz == NOSIZE) break;
		io_write_data(fd, rdwr_data, sz, NO, NULL);
		file_written_already += sz;
		if (file_written_already >= resolved_file_size) break;
	}

_donealready:
	close(fd);

	if (logfile) do_log();

	if (success_page) do_success_page();
	else rh_say("%s", success_message ? success_message : "Upload is successful.");

	rh_exit(0);
	return 0;
}
