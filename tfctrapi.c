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

void tf_ctr_set(void *ctr, const void *sctr, size_t sctrsz)
{
	TF_UNIT_TYPE usctr[TF_NR_BLOCK_UNITS];
	TF_UNIT_TYPE *uctr = (TF_UNIT_TYPE *)ctr;

	data_to_words(uctr, TF_BLOCK_SIZE);

	memset(usctr, 0, TF_BLOCK_SIZE);
	memcpy(usctr, sctr, sctrsz > TF_BLOCK_SIZE ? TF_BLOCK_SIZE : sctrsz);
	data_to_words(usctr, TF_BLOCK_SIZE);

	ctr_add(uctr, TF_NR_BLOCK_UNITS, usctr, TF_NR_BLOCK_UNITS);
	memset(usctr, 0, TF_BLOCK_SIZE);
}
