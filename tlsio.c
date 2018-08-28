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

#ifdef WITH_TLS
size_t TLS_send_pending(int fd, struct TLSContext *tlsctx)
{
	const void *buf;
	unsigned int bufsz;
	size_t sent;

	buf = tls_get_write_buffer(tlsctx, &bufsz);
	sent = io_write_data(fd, buf, (size_t)bufsz, NO, NULL);
	tls_buffer_clear(tlsctx);

	return sent;
}

rh_yesno TLS_parsemsg(struct TLSContext *tlsctx, int fd, void *tmp, size_t tsz)
{
	size_t x;

	x = io_read_data(fd, tmp, tsz, YES, NULL);
	if (x == 0 || x == NOSIZE) return NO;
	if (tls_consume_stream(tlsctx, tmp, (unsigned int)x, NULL) < 0) return NO;
	if (TLS_send_pending(fd, tlsctx) == NOSIZE) return NO;

	return YES;
}

size_t TLS_read(struct TLSContext *tlsctx, int fd, void *data, size_t szdata)
{
	size_t x;

	if (tls_established(tlsctx) <= 0) return NOSIZE;
	if (!TLS_parsemsg(tlsctx, fd, data, szdata)) return NOSIZE;
	x = (size_t)tls_read(tlsctx, data, (unsigned int)szdata);
	if (x < szdata) rh_memzero(data+x, szdata-x);

	return x;
}

size_t TLS_write(struct TLSContext *tlsctx, int fd, const void *data, size_t szdata)
{
	size_t x;

	if (tls_established(tlsctx) <= 0) return NOSIZE;
	x = (size_t)tls_write(tlsctx, data, (unsigned int)szdata);
	if (TLS_send_pending(fd, tlsctx) == NOSIZE) return NOSIZE;

	return x;
}
#endif
