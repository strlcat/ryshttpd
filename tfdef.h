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

#ifndef _THREEFISH_CIPHER_DEFINITIONS_HEADER
#define _THREEFISH_CIPHER_DEFINITIONS_HEADER

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#ifndef TF_NO_ENDIAN
#include <sys/param.h>
#else
#undef TF_BIG_ENDIAN
#endif

#define TF_UNIT_TYPE uint64_t

#ifdef TF_BIG_ENDIAN
#define TF_SWAP_FUNC htobe64
#else
#define TF_SWAP_FUNC htole64
#endif

#define TF_NR_BLOCK_BITS 512
#define TF_NR_KEY_BITS 768
#define TF_NR_BLOCK_UNITS 8
#define TF_NR_KEY_UNITS 12
#define IRR_POLY_CONST 0x125

#define TF_BYTE_TYPE uint8_t
#define TF_SIZE_UNIT (sizeof(TF_UNIT_TYPE))
#define TF_BLOCK_SIZE (TF_SIZE_UNIT * TF_NR_BLOCK_UNITS)
#define TF_KEY_SIZE (TF_SIZE_UNIT * TF_NR_KEY_UNITS)

#define TF_NR_TWEAK_UNITS 2
#define TF_NR_TWEAK_BITS 128
#define TF_TWEAK_SIZE (TF_SIZE_UNIT * TF_NR_TWEAK_UNITS)
#define TF_TWEAKEY_SIZE (TF_KEY_SIZE - (2 * TF_TWEAK_SIZE))
#define TF_NR_TWEAKEY_BITS (TF_NR_KEY_BITS - (2 * TF_NR_TWEAK_BITS))
#define TF_TWEAK_WORD1 (TF_NR_KEY_UNITS-3)
#define TF_TWEAK_WORD2 (TF_NR_KEY_UNITS-2)
#define TF_TWEAK_WORD3 (TF_NR_KEY_UNITS-1)

#define TF_TO_BITS(x) ((x) * 8)
#define TF_FROM_BITS(x) ((x) / 8)
#define TF_MAX_BITS TF_NR_BLOCK_BITS
#define TF_UNIT_BITS (TF_SIZE_UNIT * 8)

#define TF_TO_BLOCKS(x) ((x) / TF_BLOCK_SIZE)
#define TF_FROM_BLOCKS(x) ((x) * TF_BLOCK_SIZE)
#define TF_BLOCKS_TO_BYTES(x) TF_FROM_BLOCKS(x)
#define TF_BLOCKS_FROM_BYTES(x) TF_TO_BLOCKS(x)

static inline void data_to_words(void *p, size_t l)
{
#ifndef TF_NO_ENDIAN
	size_t idx;
	TF_UNIT_TYPE *P = (TF_UNIT_TYPE *)p;
	TF_UNIT_TYPE t;

	for (idx = 0; idx < (l/sizeof(TF_UNIT_TYPE)); idx++) {
		t = TF_SWAP_FUNC(P[idx]);
		P[idx] = t;
	}
#endif
}

static inline void xor_block(void *dst, const void *src, size_t sz)
{
	const size_t *sx = (const size_t *)src;
	const TF_BYTE_TYPE *usx = (const TF_BYTE_TYPE *)src;
	size_t *dx = (size_t *)dst;
	TF_BYTE_TYPE *udx = (TF_BYTE_TYPE *)dst;
	size_t sl = sz;

	for (sl = 0; sl < (sz / sizeof(size_t)); sl++) dx[sl] ^= sx[sl];
	if (sz - (sl * sizeof(size_t))) for (sl *= sizeof(size_t); sl < sz; sl++) udx[sl] ^= usx[sl];
}

static inline void ctr_inc(TF_UNIT_TYPE *x, size_t xl)
{
	size_t z;

	for (z = 0; z < xl; z++) {
		x[z] = ((x[z] + (TF_UNIT_TYPE)1) & ((TF_UNIT_TYPE)~0));
		if (x[z]) break;
	}
}

static inline void ctr_add(TF_UNIT_TYPE *x, size_t xl, const TF_UNIT_TYPE *y, size_t yl)
{
	size_t z, cf;
	TF_UNIT_TYPE t;

	for (z = 0, cf = 0; z < xl; z++) {
		t = x[z] + (z >= yl ? (TF_UNIT_TYPE)0 : y[z]) + cf;
		if (cf) cf = (x[z] >= t ? 1 : 0);
		else cf = (x[z] > t ? 1 : 0);
		x[z] = t;
	}
}

struct tfe_stream;

#define tf_convkey(k) do { data_to_words(k, TF_KEY_SIZE); } while (0)

void tf_encrypt_rawblk(TF_UNIT_TYPE *O, const TF_UNIT_TYPE *I, const TF_UNIT_TYPE *K);
void tf_decrypt_rawblk(TF_UNIT_TYPE *O, const TF_UNIT_TYPE *I, const TF_UNIT_TYPE *K);

void tf_ctr_set(void *ctr, const void *sctr, size_t sctrsz);

void tf_xts_encrypt(const void *keyx, const void *keyz, void *ctr, void *out, const void *in, size_t sz, size_t bpi);
void tf_xts_decrypt(const void *keyx, const void *keyz, void *ctr, void *out, const void *in, size_t sz, size_t bpi);

#ifdef __cplusplus
}
#endif

#endif
