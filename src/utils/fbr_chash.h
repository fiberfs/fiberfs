/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_SHA256_H_INCLUDED_
#define _FBR_SHA256_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#define FBR_SHA256_DIGEST_SIZE		(256 / 8)
#define FBR_SHA256_BLOCK_SIZE 		(512 / 8)
#define FBR_MD5_DIGEST_SIZE		16

struct fbr_sha256_ctx {
	unsigned int			magic;
#define FBR_SHA256_MAGIC		0x772F494A

	unsigned char			block[2 * FBR_SHA256_BLOCK_SIZE];
	uint32_t			h[8];

	size_t				block_len;
	size_t				total_len;
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

void fbr_sha256(const void *buffer, size_t buffer_len, uint8_t *digest);
void fbr_sha256_init(struct fbr_sha256_ctx *ctx);
void fbr_sha256_update(struct fbr_sha256_ctx *ctx, const void *buffer, size_t buffer_len);
void fbr_sha256_final(struct fbr_sha256_ctx *ctx, uint8_t *digest);

void fbr_md5_init(struct fbr_md5_ctx *md5);
void fbr_md5_update(struct fbr_md5_ctx *md5, const void *input, size_t len);
void fbr_md5_final(struct fbr_md5_ctx *md5);

#define fbr_sha256_ok(sha256)			fbr_magic_check(sha256, FBR_SHA256_MAGIC)
#define fbr_md5_ok(sha256)			fbr_magic_check(md5, FBR_MD5_MAGIC)

#endif /* _FBR_SHA256_H_INCLUDED_ */
