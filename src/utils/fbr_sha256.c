/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 * https://en.wikipedia.org/wiki/SHA-2
 *
 */

#include <string.h>

#include "fiberfs.h"
#include "fbr_chash.h"

#define _SHA_SHIFT(x, n)	(x >> n)
#define _SHA_ROT(x, n)		((x >> n) | (x << (32 - n)))
#define _SHA_CH(x, y, z)	((x & y) ^ (~x & z))
#define _SHA_MAJ(x, y, z)	((x & y) ^ (x & z) ^ (y & z))

#define _SHA256_F1(x)		(_SHA_ROT(x, 2) ^ _SHA_ROT(x, 13) ^ _SHA_ROT(x, 22))
#define _SHA256_F2(x)		(_SHA_ROT(x, 6) ^ _SHA_ROT(x, 11) ^ _SHA_ROT(x, 25))
#define _SHA256_F3(x)		(_SHA_ROT(x, 7) ^ _SHA_ROT(x, 18) ^ _SHA_SHIFT(x, 3))
#define _SHA256_F4(x)		(_SHA_ROT(x, 17) ^ _SHA_ROT(x, 19) ^ _SHA_SHIFT(x, 10))

#define _UNPACK32(src, dest)					\
{								\
	*((dest) + 3) = (uint8_t)(src);				\
	*((dest) + 2) = (uint8_t)((src) >> 8);			\
	*((dest) + 1) = (uint8_t)((src) >> 16);			\
	*(dest) = (uint8_t)((src) >> 24);			\
}

#define _PACK32(src, dest)					\
{								\
	*(dest) = ((uint32_t) *((src) + 3))			\
		| ((uint32_t) *((src) + 2) << 8)		\
		| ((uint32_t) *((src) + 1) << 16)		\
		| ((uint32_t) *(src) << 24);			\
}

#define _SHA256_EXT(i, w)					\
{								\
	(w)[i] = _SHA256_F4((w)[i - 2]) + (w)[i - 7]		\
		+ _SHA256_F3((w)[i - 15]) + (w)[i - 16];	\
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
_sha256_calc(struct fbr_sha256_ctx *ctx, const uint8_t *block, size_t block_count)
{
	assert_dev(ctx);
	assert_dev(block);

	for (size_t i = 0; i < block_count; i++) {
		uint32_t w[64];
		uint32_t v[8];

		for (size_t j = 0; j < 16; j++) {
			_PACK32(&block[j * 4], &w[j]);
		}
		for (size_t j = 16; j < 64; j++) {
			_SHA256_EXT(j, w);
		}
		for (size_t j = 0; j < 8; j++) {
			v[j] = ctx->h[j];
		}
		for (size_t j = 0; j < 64; j++) {
			uint32_t t1 = v[7] + _SHA256_F2(v[4]) + _SHA_CH(v[4], v[5], v[6])
				+ _SHA256_K[j] + w[j];
			uint32_t t2 = _SHA256_F1(v[0]) + _SHA_MAJ(v[0], v[1], v[2]);
			v[7] = v[6];
			v[6] = v[5];
			v[5] = v[4];
			v[4] = v[3] + t1;
			v[3] = v[2];
			v[2] = v[1];
			v[1] = v[0];
			v[0] = t1 + t2;
		}
		for (size_t j = 0; j < 8; j++) {
			ctx->h[j] += v[j];
		}

		block += FBR_SHA256_BLOCK_SIZE;
	}
}

void
fbr_sha256(const void *buffer, size_t buffer_len, uint8_t *digest, size_t digest_len)
{
	assert(digest);

	struct fbr_sha256_ctx ctx;

	fbr_sha256_init(&ctx);
	fbr_sha256_update(&ctx, buffer, buffer_len);
	fbr_sha256_final(&ctx, digest, digest_len);
}

void
fbr_sha256_init(struct fbr_sha256_ctx *ctx)
{
	assert(ctx);

	fbr_zero(ctx);
	ctx->magic = FBR_SHA256_MAGIC;

	for (size_t i = 0; i < 8; i++) {
		ctx->h[i] = _SHA256_H0[i];
	}
}

void
fbr_sha256_update(struct fbr_sha256_ctx *ctx, const void *buffer, size_t buffer_len)
{
	fbr_sha256_ok(ctx);
	assert_dev(ctx->block_len < FBR_SHA256_BLOCK_SIZE);
	assert(buffer || !buffer_len);

	ctx->total_len += buffer_len;

	size_t block_free = FBR_SHA256_BLOCK_SIZE - ctx->block_len;
	size_t block_copy = buffer_len < block_free ? buffer_len : block_free;

	memcpy(&ctx->block[ctx->block_len], buffer, block_copy);

	ctx->block_len += block_copy;
	buffer_len -= block_copy;

	if (ctx->block_len < FBR_SHA256_BLOCK_SIZE) {
		assert_zero_dev(buffer_len);
		return;
	}

	const uint8_t *block_buffer = (const uint8_t*)buffer + block_copy;
	size_t block_count = buffer_len / FBR_SHA256_BLOCK_SIZE;

	_sha256_calc(ctx, ctx->block, 1);

	if (block_count) {
		_sha256_calc(ctx, block_buffer, block_count);
	}

	size_t block_done = block_count * FBR_SHA256_BLOCK_SIZE;
	assert(block_done <= buffer_len);
	block_buffer += block_done;
	buffer_len -= block_done;

	if (buffer_len) {
		memcpy(ctx->block, block_buffer, buffer_len);
	}

	ctx->block_len = buffer_len;
}

void fbr_sha256_final(struct fbr_sha256_ctx *ctx, uint8_t *digest, size_t digest_len)
{
	fbr_sha256_ok(ctx);
	assert_dev(ctx->block_len < FBR_SHA256_BLOCK_SIZE);
	assert(digest);
	assert(digest_len >= FBR_SHA256_DIGEST_SIZE);

	size_t block_count = 1;
	if (ctx->block_len > FBR_SHA256_BLOCK_SIZE - 9) {
		block_count++;
	}

	size_t total_bits = ctx->total_len * 8;
	size_t block_size = block_count * FBR_SHA256_BLOCK_SIZE;

	memset(ctx->block + ctx->block_len, 0, block_size - ctx->block_len);
	ctx->block[ctx->block_len] = 0x80;
	_UNPACK32(total_bits, ctx->block + block_size - 4);

	_sha256_calc(ctx, ctx->block, block_count);

	for (size_t i = 0 ; i < 8; i++) {
		_UNPACK32(ctx->h[i], &digest[i * 4]);
	}

	fbr_zero(ctx);
}

static void
_hmac_key_init(const void *key, size_t key_len, uint8_t *key_block, size_t key_block_len,
    int inner)
{
	assert_dev(key);
	assert_dev(key_len);
	assert_dev(key_block);
	assert_dev(key_block_len == FBR_SHA256_BLOCK_SIZE);

	memset(key_block, 0, key_block_len);
	if (key_len > key_block_len) {
		fbr_sha256(key, key_len, key_block, key_block_len);
	} else {
		memcpy(key_block, key, key_len);
	}

	for (size_t i = 0; i < key_block_len; i++) {
		key_block[i] ^= inner ? 0x36 : 0x5c;
	}
}

void
fbr_hmac_sha256_init(struct fbr_sha256_ctx *ctx, const void *key, size_t key_len)
{
	assert(ctx);
	assert(key);
	assert(key_len);

	fbr_sha256_init(ctx);
	fbr_sha256_ok(ctx);

	uint8_t key_block[FBR_SHA256_BLOCK_SIZE];
	_hmac_key_init(key, key_len, key_block, sizeof(key_block), 1);

	fbr_sha256_update(ctx, key_block, sizeof(key_block));
}

void
fbr_hmac_sha256_final(struct fbr_sha256_ctx *ctx, const void *key, size_t key_len, uint8_t *digest,
    size_t digest_len)
{
	fbr_sha256_ok(ctx);
	assert(digest);
	assert(digest_len >= FBR_SHA256_DIGEST_SIZE);

	fbr_sha256_final(ctx, digest, digest_len);

	uint8_t key_block[FBR_SHA256_BLOCK_SIZE];
	_hmac_key_init(key, key_len, key_block, sizeof(key_block), 0);

	fbr_sha256_init(ctx);
	fbr_sha256_ok(ctx);

	fbr_sha256_update(ctx, key_block, sizeof(key_block));
	fbr_sha256_update(ctx, digest, FBR_SHA256_DIGEST_SIZE);

	fbr_sha256_final(ctx, digest, digest_len);
}
