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

#ifndef _THREEFISH_SKEIN_DEFINITIONS_HEADER
#define _THREEFISH_SKEIN_DEFINITIONS_HEADER

#include "tfdef.h"

#define SKEIN_VERSION 1
#define SKEIN_ID 0x33414853

#define SKEIN_BLOCK_CFG ((TF_UNIT_TYPE)4 << 56)
#define SKEIN_BLOCK_MSG ((TF_UNIT_TYPE)48 << 56)
#define SKEIN_BLOCK_OUT ((TF_UNIT_TYPE)63 << 56)
#define SKEIN_FLAG_FIRST ((TF_UNIT_TYPE)1 << 62)
#define SKEIN_FLAG_LAST ((TF_UNIT_TYPE)1 << 63)

#define SKEIN_DIGEST_SIZE TF_BLOCK_SIZE


#ifdef __cplusplus
extern "C" {
#endif

struct skein {
	TF_UNIT_TYPE key[TF_NR_KEY_UNITS];
	TF_BYTE_TYPE carry_block[TF_BLOCK_SIZE];
	size_t carry_bytes;
	size_t bits;
};

void skein_init_key(struct skein *sk, const void *ukey, size_t bits);
void skein_init(struct skein *sk, size_t bits);
void skein_update(struct skein *sk, const void *msg, size_t msgsz);
void skein_final(void *result, struct skein *sk);

#ifdef __cplusplus
}
#endif

#endif
