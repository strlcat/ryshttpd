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
 * This program is modified version of tfcrypt.c from tfcipher library.
 * It is modified to ask for password.
 */

#include "httpd.h"
#include "getpasswd.h"

extern char *xgetpass(const char *);

#define DATASIZE 16384

static char keyx[TF_KEY_SIZE], keyz[TF_KEY_SIZE], ctr[TF_BLOCK_SIZE];
static char srcblk[DATASIZE], dstblk[DATASIZE];
static struct skein sk;
static int will_exit;
static rh_yesno do_encrypt;
static rh_fsize range_start;

static void htcusage(void)
{
	printf("\nusage: htcrypt [-e] [-s offset] srcfile dstfile\n\n");
	printf("Decrypts srcfile into dstfile with password using XTS mode.\n");
	printf("htcrypt will ask you for password to perform operation.\n");
	printf("Specify \"-\" as srcfile to read data from stdin.\n");
	printf("Specify \"-\" as dstfile to write data to stdout.\n");
	printf("Specify optional '-s offset' value to first value used to download\n");
	printf("a portion of file with \"Range: start-end\" HTTP header.\n\n");
	exit(1);
}

static void htcerror(const char *s)
{
	perror(s);
	exit(2);
}

static rh_yesno is_str_hxnum(const void *p, size_t n)
{
	const char *s = (const char *)p;

	while (*s && n > 0) {
		if (!isxdigit(*s)) return NO;
		s++; n--;
	}
	return YES;
}

int main(int argc, char **argv)
{
	int ifd, ofd, c;
	char *infname, *onfname;
	size_t lio, lrem, ldone, t;
	char *pblk;

	while ((c = getopt(argc, argv, "es:")) != -1) {
		switch (c) {
			case 'e': do_encrypt = YES; break;
			case 's': range_start = (rh_fsize)strtoull(optarg, NULL, 0) / TF_BLOCK_SIZE; break;
			default: htcusage(); break;
		}
	}

	if (!argv[optind]) htcusage();
	infname = argv[optind];
	if (!argv[optind+1]) htcusage();
	onfname = argv[optind+1];
	if (!infname || !onfname) htcusage();

	if (!strcmp(infname, "-")) ifd = 0;
	else {
#ifdef O_LARGEFILE
		ifd = open(infname, O_RDONLY | O_LARGEFILE);
#else
		ifd = open(infname, O_RDONLY);
#endif
		if (ifd == -1) htcerror(infname);
	}

	pblk = getenv("HTCPASSWD");
	if (!pblk) {
		pblk = xgetpass("Enter file password: ");
		if (!pblk) htcusage();
	}

	skein_init(&sk, TF_TO_BITS(TF_KEY_SIZE));
	skein_update(&sk, pblk, strlen(pblk));
	skein_final(keyx, &sk);
	tf_convkey(keyx);
	memset(pblk, 0, strlen(pblk));

	skein_init(&sk, TF_TO_BITS(TF_KEY_SIZE));
	skein_update(&sk, keyx, TF_KEY_SIZE);
	skein_final(keyz, &sk);
	tf_convkey(keyz);

	skein_init(&sk, TF_TO_BITS(TF_BLOCK_SIZE));
	skein_update(&sk, keyx, TF_KEY_SIZE);
	skein_final(ctr, &sk);
	tf_ctr_set(ctr, &range_start, sizeof(rh_fsize));

	if (!strcmp(onfname, "-")) ofd = 1;
	else {
		ofd = creat(onfname, 0666);
		if (ofd == -1) htcerror(onfname);
	}

	will_exit = 0;
	while (1) {
		if (will_exit) break;
		pblk = srcblk;
		ldone = 0;
		lrem = sizeof(srcblk);
_ragain:	lio = read(ifd, pblk, lrem);
		if (lio == 0) will_exit = 1;
		if (lio != NOSIZE) ldone += lio;
		else htcerror(infname);
		if (lio && lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _ragain;
		}

		if (do_encrypt) tf_xts_encrypt(keyx, keyz, ctr, dstblk, srcblk, ldone, 1);
		else tf_xts_decrypt(keyx, keyz, ctr, dstblk, srcblk, ldone, 1);

		pblk = dstblk;
		lrem = ldone;
		ldone = 0;
_wagain:	lio = write(ofd, pblk, lrem);
		if (lio != NOSIZE) ldone += lio;
		else htcerror(onfname);
		if (lio < lrem) {
			pblk += lio;
			lrem -= lio;
			goto _wagain;
		}
	}

	close(ifd);
	close(ofd);

	return 0;
}
