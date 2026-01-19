/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _CHTTP_GZIP_H_INCLUDED_
#define _CHTTP_GZIP_H_INCLUDED_

#include <stddef.h>

#include "chttp.h"
#include "compress/fbr_gzip.h"

size_t chttp_gzip_read_body(struct chttp_context *ctx, void *output, size_t output_len);
void chttp_gzip_register(struct chttp_context *ctx, struct fbr_gzip *gzip,
	void *buffer, size_t buffer_len);
void chttp_gzip_send_chunk(struct fbr_gzip *gzip, struct chttp_addr *addr,
	const void *input, size_t input_len);

#ifdef FBR_ZLIB

size_t chttp_zlib_read_body(struct chttp_context *ctx, unsigned char *output, size_t output_len);
void chttp_zlib_send_chunk(struct fbr_zlib *zlib, struct chttp_addr *addr,
	const unsigned char *input, size_t input_len);
void chttp_zlib_register(struct fbr_zlib *zlib, unsigned char *buffer, size_t buffer_len);

#endif /* FBR_ZLIB */

#endif /* _CHTTP_GZIP_H_INCLUDED_ */
