/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Last update: 02/02/2007
 * Issue date:  04/30/2005
 *
 * Copyright (C) 2013, Con Kolivas <kernel@kolivas.org>
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * https://github.com/ckolivas/cgminer/blob/master/sha2.c
 *
 */

#include <string.h>

#include "fiberfs.h"
#include "fbr_sha256.h"

#define _SHFR(x, n)		(x >> n)
#define _ROTR(x, n)		((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define _CH(x, y, z)		((x & y) ^ (~x & z))
#define _MAJ(x, y, z)		((x & y) ^ (x & z) ^ (y & z))

#define _SHA256_F1(x)		(_ROTR(x,  2) ^ _ROTR(x, 13) ^ _ROTR(x, 22))
#define _SHA256_F2(x)		(_ROTR(x,  6) ^ _ROTR(x, 11) ^ _ROTR(x, 25))
#define _SHA256_F3(x)		(_ROTR(x,  7) ^ _ROTR(x, 18) ^ _SHFR(x,  3))
#define _SHA256_F4(x)		(_ROTR(x, 17) ^ _ROTR(x, 19) ^ _SHFR(x, 10))

#define _UNPACK32(x, str)				\
{							\
	*((str) + 3) = (uint8_t) ((x));			\
	*((str) + 2) = (uint8_t) ((x) >>  8);		\
	*((str) + 1) = (uint8_t) ((x) >> 16);		\
	*((str) + 0) = (uint8_t) ((x) >> 24);		\
}

#define _PACK32(str, x)					\
{							\
	*(x) = ((uint32_t) *((str) + 3))		\
		| ((uint32_t) *((str) + 2) <<  8)	\
		| ((uint32_t) *((str) + 1) << 16)	\
		| ((uint32_t) *((str) + 0) << 24);	\
}

#define _SHA256_SCR(i)					\
{							\
	w[i] = _SHA256_F4(w[i -  2]) + w[i -  7]	\
		+ _SHA256_F3(w[i - 15]) + w[i - 16];	\
}

static uint32_t _SHA256_H0[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static uint32_t _SHA256_K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void
_sha256_transf(struct fbr_sha256_ctx *ctx, const uint8_t *message, size_t block_nb)
{
	assert_dev(ctx);
	assert_dev(message);

	for (size_t i = 0; i < block_nb; i++) {
		const uint8_t *sub_block = message + (i << 6);
		uint32_t w[64];
		uint32_t wv[8];

		for (size_t j = 0; j < 16; j++) {
			_PACK32(&sub_block[j << 2], &w[j]);
		}
		for (size_t j = 16; j < 64; j++) {
			_SHA256_SCR(j);
		}
		for (size_t j = 0; j < 8; j++) {
			wv[j] = ctx->h[j];
		}
		for (size_t j = 0; j < 64; j++) {
			uint32_t t1 = wv[7] + _SHA256_F2(wv[4]) + _CH(wv[4], wv[5], wv[6])
				+ _SHA256_K[j] + w[j];
			uint32_t t2 = _SHA256_F1(wv[0]) + _MAJ(wv[0], wv[1], wv[2]);
			wv[7] = wv[6];
			wv[6] = wv[5];
			wv[5] = wv[4];
			wv[4] = wv[3] + t1;
			wv[3] = wv[2];
			wv[2] = wv[1];
			wv[1] = wv[0];
			wv[0] = t1 + t2;
		}
		for (size_t j = 0; j < 8; j++) {
			ctx->h[j] += wv[j];
		}
	}
}

void
fbr_sha256(const void *buffer, size_t buffer_len, uint8_t *digest)
{
	assert(digest);

	struct fbr_sha256_ctx ctx;

	fbr_sha256_init(&ctx);
	fbr_sha256_update(&ctx, buffer, buffer_len);
	fbr_sha256_final(&ctx, digest);
}

void
fbr_sha256_init(struct fbr_sha256_ctx *ctx)
{
	assert(ctx);

	for (size_t i = 0; i < 8; i++) {
		ctx->h[i] = _SHA256_H0[i];
	}

	ctx->len = 0;
	ctx->tot_len = 0;
}

void
fbr_sha256_update(struct fbr_sha256_ctx *ctx, const void *buffer, size_t buffer_len)
{
	assert(ctx);
	assert(buffer || !buffer_len);

	size_t tmp_len = FBR_SHA256_BLOCK_SIZE - ctx->len;
	size_t rem_len = buffer_len < tmp_len ? buffer_len : tmp_len;

	memcpy(&ctx->block[ctx->len], buffer, rem_len);

	if (ctx->len + buffer_len < FBR_SHA256_BLOCK_SIZE) {
		ctx->len += buffer_len;
		return;
	}

	size_t new_len = buffer_len - rem_len;
	size_t block_nb = new_len / FBR_SHA256_BLOCK_SIZE;

	const uint8_t *shifted_message = (const uint8_t*)buffer + rem_len;

	_sha256_transf(ctx, ctx->block, 1);
	_sha256_transf(ctx, shifted_message, block_nb);

	rem_len = new_len % FBR_SHA256_BLOCK_SIZE;

	memcpy(ctx->block, &shifted_message[block_nb << 6], rem_len);

	ctx->len = rem_len;
	ctx->tot_len += (block_nb + 1) << 6;
}

void fbr_sha256_final(struct fbr_sha256_ctx *ctx, uint8_t *digest)
{
	assert(ctx);
	assert(digest);

	size_t block_nb = (1 + ((FBR_SHA256_BLOCK_SIZE - 9) < (ctx->len % FBR_SHA256_BLOCK_SIZE)));

	size_t len_b = (ctx->tot_len + ctx->len) << 3;
	size_t pm_len = block_nb << 6;

	memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
	ctx->block[ctx->len] = 0x80;
	_UNPACK32(len_b, ctx->block + pm_len - 4);

	_sha256_transf(ctx, ctx->block, block_nb);

	for (size_t i = 0 ; i < 8; i++) {
		_UNPACK32(ctx->h[i], &digest[i << 2]);
	}
}
