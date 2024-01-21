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

#include <string.h>
#include "tfdef.h"

static inline void xts_mult_x(TF_UNIT_TYPE *x)
{
	size_t i, t, tt;

	for (i = t = 0; i < TF_NR_BLOCK_UNITS; i++) {
		tt = x[i] >> (TF_UNIT_BITS-1);
		x[i] = ((x[i] << 1) | t) & ((TF_UNIT_TYPE)~0);
		t = tt;
	}
	if (tt) x[0] ^= IRR_POLY_CONST;
}

static void xts_decrypt(const void *keyx, const void *keyz, void *ctr, void *out, const void *in, size_t sz)
{
	const TF_BYTE_TYPE *uin = (const TF_BYTE_TYPE *)in;
	TF_BYTE_TYPE *uout = (TF_BYTE_TYPE *)out, *s, *d;
	TF_UNIT_TYPE x[TF_NR_BLOCK_UNITS], y[TF_NR_BLOCK_UNITS];
	TF_UNIT_TYPE tctr[TF_NR_BLOCK_UNITS], zctr[TF_NR_BLOCK_UNITS];
	TF_UNIT_TYPE *uctr = (TF_UNIT_TYPE *)ctr;
	const TF_UNIT_TYPE *ukeyx = (const TF_UNIT_TYPE *)keyx, *ukeyz = (const TF_UNIT_TYPE *)keyz;
	size_t sl = sz, i;

	tf_encrypt_rawblk(tctr, uctr, ukeyz);

	if (sl >= (TF_BLOCK_SIZE * 2)) {
		do {
_last:			memcpy(x, uin, TF_BLOCK_SIZE);
			uin += TF_BLOCK_SIZE;
			data_to_words(x, TF_BLOCK_SIZE);

			ctr_inc(uctr, TF_NR_BLOCK_UNITS);
			for (i = 0; i < TF_NR_BLOCK_UNITS; i++) y[i] = x[i] ^ tctr[i];
			tf_decrypt_rawblk(x, y, ukeyx);
			for (i = 0; i < TF_NR_BLOCK_UNITS; i++) x[i] ^= tctr[i];

			xts_mult_x(tctr);

			data_to_words(x, TF_BLOCK_SIZE);
			memcpy(uout, x, TF_BLOCK_SIZE);
			uout += TF_BLOCK_SIZE;
		} while ((sl -= TF_BLOCK_SIZE) >= (TF_BLOCK_SIZE * 2));
	}

	if (sl) {
		if (sl-TF_BLOCK_SIZE == 0) goto _last;
		if (sl < TF_BLOCK_SIZE) {
			memset(x, 0, TF_BLOCK_SIZE);
			memcpy(x, uin, sl);
			data_to_words(x, TF_BLOCK_SIZE);

			ctr_inc(uctr, TF_NR_BLOCK_UNITS);
			tf_encrypt_rawblk(y, uctr, ukeyx);
			for (i = 0; i < TF_NR_BLOCK_UNITS; i++) y[i] ^= x[i];

			data_to_words(y, TF_BLOCK_SIZE);
			memcpy(uout, y, sl);

			goto _done;
		}

		memcpy(x, uin, TF_BLOCK_SIZE);
		uin += TF_BLOCK_SIZE;
		data_to_words(x, TF_BLOCK_SIZE);

		ctr_inc(uctr, TF_NR_BLOCK_UNITS);
		memcpy(zctr, tctr, TF_BLOCK_SIZE);
		xts_mult_x(tctr);

		tf_encrypt_rawblk(tctr, uctr, ukeyz);

		for (i = 0; i < TF_NR_BLOCK_UNITS; i++) x[i] ^= tctr[i];
		tf_decrypt_rawblk(x, x, ukeyx);
		for (i = 0; i < TF_NR_BLOCK_UNITS; i++) x[i] ^= tctr[i];

		sl -= TF_BLOCK_SIZE;
		memcpy(y, uin, sl);
		data_to_words(y, sl);

		s = (TF_BYTE_TYPE *)y;
		d = (TF_BYTE_TYPE *)x;
		memcpy(s+sl, d+sl, TF_BLOCK_SIZE-sl);
		for (i = 0; i < TF_NR_BLOCK_UNITS; i++) y[i] ^= zctr[i];
		tf_decrypt_rawblk(y, y, ukeyx);
		for (i = 0; i < TF_NR_BLOCK_UNITS; i++) y[i] ^= zctr[i];

		data_to_words(y, TF_BLOCK_SIZE);
		memcpy(uout, y, TF_BLOCK_SIZE);
		uout += TF_BLOCK_SIZE;

		data_to_words(x, TF_BLOCK_SIZE);
		memcpy(uout, x, sl);
	}

_done:	memset(tctr, 0, TF_BLOCK_SIZE);
	memset(zctr, 0, TF_BLOCK_SIZE);
	memset(x, 0, TF_BLOCK_SIZE);
	memset(y, 0, TF_BLOCK_SIZE);
}

void tf_xts_decrypt(const void *keyx, const void *keyz, void *ctr, void *out, const void *in, size_t sz, size_t bpi)
{
	const TF_BYTE_TYPE *uin = (const TF_BYTE_TYPE *)in;
	TF_BYTE_TYPE *uout = (TF_BYTE_TYPE *)out;
	size_t sl = sz, sx = TF_BLOCKS_TO_BYTES(bpi);

	if (sl >= sx) {
		do {
			xts_decrypt(keyx, keyz, ctr, uout, uin, sx);
			uout += sx;
			uin += sx;
		} while ((sl -= sx) >= sx);
	}

	if (sl) xts_decrypt(keyx, keyz, ctr, uout, uin, sl);
}
