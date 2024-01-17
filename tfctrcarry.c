/*
 * tfctrcarry.c: CTR mode with simple tail carrying between two separate calls.
 *
 * Copyright (C) 2024 Andrey Rys. All Rights reserved.
 *
 * Licensed under terms described in package where it was located.
 * See COPYRIGHT or LICENSE or any other included licensing material.
 */

#include <string.h>
#include "tfdef.h"

void tf_ctr_crypt_carry(const void *key, void *ctr, void *out, const void *in, size_t sz, void *carry, size_t *crem)
{
	const TF_BYTE_TYPE *uin = (const TF_BYTE_TYPE *)in;
	TF_BYTE_TYPE *uout = (TF_BYTE_TYPE *)out;
	TF_UNIT_TYPE x[TF_NR_BLOCK_UNITS], y[TF_NR_BLOCK_UNITS];
	TF_UNIT_TYPE *uctr = (TF_UNIT_TYPE *)ctr;
	const TF_UNIT_TYPE *ukey = (const TF_UNIT_TYPE *)key;
	size_t sl = sz, i;

	if (carry && crem && *crem > 0 && *crem <= TF_BLOCK_SIZE) {
		size_t n = *crem;

		memcpy(x, uin, n);
		uin += n;
		data_to_words(x, TF_BLOCK_SIZE);

		memcpy(y, carry, n);
		for (i = 0; i < TF_NR_BLOCK_UNITS; i++) y[i] ^= x[i];

		data_to_words(y, TF_BLOCK_SIZE);
		memcpy(uout, y, n);
		uout += n;
		sl -= n;

		*crem = 0;
	}

	if (sl >= TF_BLOCK_SIZE) {
		do {
			memcpy(x, uin, TF_BLOCK_SIZE);
			uin += TF_BLOCK_SIZE;
			data_to_words(x, TF_BLOCK_SIZE);

			ctr_inc(uctr, TF_NR_BLOCK_UNITS);
			tf_encrypt_rawblk(y, uctr, ukey);
			for (i = 0; i < TF_NR_BLOCK_UNITS; i++) y[i] ^= x[i];

			data_to_words(y, TF_BLOCK_SIZE);
			memcpy(uout, y, TF_BLOCK_SIZE);
			uout += TF_BLOCK_SIZE;
		} while ((sl -= TF_BLOCK_SIZE) >= TF_BLOCK_SIZE);
	}

	if (sl) {
		memset(x, 0, TF_BLOCK_SIZE);
		memcpy(x, uin, sl);
		data_to_words(x, TF_BLOCK_SIZE);

		ctr_inc(uctr, TF_NR_BLOCK_UNITS);
		tf_encrypt_rawblk(y, uctr, ukey);

		if (carry) {
			TF_BYTE_TYPE *p = (TF_BYTE_TYPE *)y;
			memcpy(carry, p+sl, TF_BLOCK_SIZE-sl);
			data_to_words(carry, TF_BLOCK_SIZE-sl);
			*crem = TF_BLOCK_SIZE-sl;
		}

		for (i = 0; i < TF_NR_BLOCK_UNITS; i++) y[i] ^= x[i];

		data_to_words(y, TF_BLOCK_SIZE);
		memcpy(uout, y, sl);
	}

	memset(x, 0, TF_BLOCK_SIZE);
	memset(y, 0, TF_BLOCK_SIZE);
}
