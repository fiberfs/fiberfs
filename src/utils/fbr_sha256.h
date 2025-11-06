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

struct fbr_sha256_ctx {
	size_t				len;
	size_t				tot_len;
	unsigned char			block[2 * FBR_SHA256_BLOCK_SIZE];
	uint32_t			h[8];
};

void fbr_sha256(const void *buffer, size_t buffer_len, uint8_t *digest);
void fbr_sha256_init(struct fbr_sha256_ctx *ctx);
void fbr_sha256_update(struct fbr_sha256_ctx *ctx, const void *buffer, size_t buffer_len);
void fbr_sha256_final(struct fbr_sha256_ctx *ctx, uint8_t *digest);

#endif /* _FBR_SHA256_H_INCLUDED_ */
