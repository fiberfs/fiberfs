/*
 * Copyright (c) 2024-2025 FiberFS
 *
 */

#ifndef _FBR_GZIP_H_INCLUDED_
#define _FBR_GZIP_H_INCLUDED_

#include <stddef.h>

enum fbr_gzip_status {
	FBR_GZIP_MORE_BUFFER = -1,
	FBR_GZIP_DONE = 0,
	FBR_GZIP_ERROR = 1
};

#ifdef FBR_ZLIB
#include "gzip_zlib.h"
#define fbr_gzip fbr_zlib
#else
struct fbr_gzip {
	int error;
	int status;
};
#endif

int fbr_gzip_enabled(void);
struct fbr_gzip *fbr_gzip_inflate_alloc(void);
struct fbr_gzip *fbr_gzip_deflate_alloc(void);
void fbr_gzip_inflate_init(struct fbr_gzip *gzip);
void fbr_gzip_deflate_init(struct fbr_gzip *gzip);
void fbr_gzip_flate(struct fbr_gzip *gzip, const void *input, size_t input_len,
	void *output, size_t output_len, size_t *written, int finish_deflate);
void fbr_gzip_free(void *gzip_priv);

struct chttp_context;
struct chttp_addr;

size_t chttp_gzip_read_body(struct chttp_context *ctx, void *output, size_t output_len);
void chttp_gzip_register(struct chttp_context *ctx, struct fbr_gzip *gzip,
	void *buffer, size_t buffer_len);
void chttp_gzip_send_chunk(struct fbr_gzip *gzip, struct chttp_addr *addr,
	const void *input, size_t input_len);

#endif /* _FBR_GZIP_H_INCLUDED_ */
