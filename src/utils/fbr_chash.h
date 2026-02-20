/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_SHA256_H_INCLUDED_
#define _FBR_SHA256_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#ifdef CHTTP_OPENSSL
#include <openssl/hmac.h>
#include <openssl/sha.h>
#endif

#define FBR_SHA256_DIGEST_SIZE		32
#define FBR_SHA256_BLOCK_SIZE 		64
#define FBR_MD5_DIGEST_SIZE		16

struct fbr_sha256_ctx {
	unsigned int			magic;
#define FBR_SHA256_MAGIC		0x772F494A

	fbr_bitflag_t			openssl:1;
	fbr_bitflag_t			openssl_hmac:1;

#ifdef CHTTP_OPENSSL
	SHA256_CTX			openssl_ctx;
	HMAC_CTX			*openssl_hmac_ctx;
#endif

	uint8_t				block[FBR_SHA256_BLOCK_SIZE * 2];
	uint32_t			h[8];

	size_t				block_len;
	size_t				total_bytes;
};

struct fbr_md5_ctx {
	unsigned int			magic;
#define FBR_MD5_MAGIC			0x4E4330A7

	int				ready;

	uint32_t			i[2];
	uint32_t			buf[4];
	unsigned char			in[64];
	unsigned char			digest[FBR_MD5_DIGEST_SIZE];
};

void fbr_sha256(const void *buffer, size_t buffer_len, uint8_t *digest, size_t digest_len);
void fbr_sha256_init(struct fbr_sha256_ctx *ctx, int use_native);
void fbr_sha256_update(struct fbr_sha256_ctx *ctx, const void *buffer, size_t buffer_len);
void fbr_sha256_final(struct fbr_sha256_ctx *ctx, uint8_t *digest, size_t digest_len);

void fbr_hmac_sha256_init(struct fbr_sha256_ctx *ctx, const void *key, size_t key_len,
	int use_native);
void fbr_hmac_sha256_final(struct fbr_sha256_ctx *ctx, const void *key, size_t key_len,
	uint8_t *digest, size_t digest_len);

void fbr_md5_init(struct fbr_md5_ctx *md5);
void fbr_md5_update(struct fbr_md5_ctx *md5, const void *input, size_t len);
void fbr_md5_final(struct fbr_md5_ctx *md5);

#define fbr_sha256_ok(sha256)			fbr_magic_check(sha256, FBR_SHA256_MAGIC)
#define fbr_md5_ok(sha256)			fbr_magic_check(md5, FBR_MD5_MAGIC)

#endif /* _FBR_SHA256_H_INCLUDED_ */
