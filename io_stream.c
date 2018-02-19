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

/*
 * That's like sendfile, but much more complex.
 * The aim is to avoid using sendfile completely,
 * doing all I/O as much portably as possible.
 * Original code is from my tfcrypt I/O layer.
 */

#include "httpd.h"

static size_t BLK_LEN_ADJ(rh_fsize filelen, rh_fsize read_already, size_t blklen)
{
	if (filelen == NOFSIZE) return blklen;
	return ((filelen - read_already) >= blklen) ? blklen : (filelen - read_already);
}

rh_yesno io_stream_file(struct io_stream_args *ios_args)
{
	char *pblk;
	rh_fsize total_to_read;
	size_t ld, lr, lb, li;
	rh_yesno do_stop = NO;

	if (!ios_args) return NO;

	if (!ios_args->rdfn || !ios_args->wrfn || !ios_args->skfn) {
		ios_args->error = EINVAL;
		return NO;
	}

	if (ios_args->file_size != NOFSIZE) {
		if ((ios_args->read_to > ios_args->file_size)
		|| ios_args->read_to == 0)
			ios_args->read_to = ios_args->file_size;
		if (ios_args->start_from > ios_args->file_size)
			ios_args->start_from = 0;
		if (ios_args->start_from > ios_args->read_to)
			ios_args->start_from = 0;

		if (ios_args->start_from > 0) {
			if (ios_args->skfn(ios_args->fn_args, ios_args->start_from) == NOFSIZE) {
				ios_args->error = errno;
				ios_args->status = IOS_SEEK_ERROR;
				return NO;
			}
		}
		total_to_read = ios_args->read_to - ios_args->start_from;
	}
	else total_to_read = NOFSIZE;

	/* tfcrypt fault tolerant io code */
	while (1) {
		if (do_stop) break;
		pblk = ios_args->workbuf;
		ld = 0;
		lr = lb = BLK_LEN_ADJ(total_to_read, ios_args->nr_written, ios_args->wkbufsz);
_ragain:	li = ios_args->rdfn(ios_args->fn_args, pblk, lr);
		if (li == 0) do_stop = YES;
		if (li == NOSIZE) {
			ios_args->error = errno;
			ios_args->status = IOS_READ_ERROR;
			return NO;
		}
		else ld += li;
		if (li && li < lr) {
			pblk += li;
			lr -= li;
			goto _ragain;
		}

		pblk = ios_args->workbuf;
		lr = ld;
		ld = 0;
_wagain:	li = ios_args->wrfn(ios_args->fn_args, pblk, lr);
		if (li == NOSIZE) {
			ios_args->error = errno;
			ios_args->status = IOS_WRITE_ERROR;
			return NO;
		}
		else ld += li;
		if (li < lr) {
			pblk += li;
			lr -= li;
			goto _wagain;
		}

		ios_args->nr_written += ld;
		if (total_to_read != NOFSIZE
		&& ios_args->nr_written >= total_to_read) break;
	}

	ios_args->error = 0;
	ios_args->status = IOS_ALL_OK;
	return YES;
}
