/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
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
#include "fbr_gzip_zlib.h"
#define fbr_gzip fbr_zlib
#else
struct fbr_gzip {
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

#endif /* _FBR_GZIP_H_INCLUDED_ */
