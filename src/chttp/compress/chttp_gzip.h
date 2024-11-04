/*
 * Copyright (c) 2024 chttp
 *
 */

#ifndef _CHTTP_GZIP_H_INCLUDED_
#define _CHTTP_GZIP_H_INCLUDED_

#include <stddef.h>

enum chttp_gzip_status {
	CHTTP_GZIP_MORE_BUFFER = -1,
	CHTTP_GZIP_DONE = 0,
	CHTTP_GZIP_ERROR = 1
};

#ifdef CHTTP_ZLIB
#include "gzip_zlib.h"
#define chttp_gzip chttp_zlib
#else
struct chttp_gzip {
	int error;
};
#endif

struct chttp_context;
struct chttp_addr;

int chttp_gzip_enabled(void);
struct chttp_gzip *chttp_gzip_inflate_alloc(void);
struct chttp_gzip *chttp_gzip_deflate_alloc(void);
void chttp_gzip_inflate_init(struct chttp_gzip *gzip);
void chttp_gzip_deflate_init(struct chttp_gzip *gzip);
void chttp_gzip_free(void *gzip_priv);
size_t chttp_gzip_read_body(struct chttp_context *ctx, void *output, size_t output_len);
void chttp_gzip_register(struct chttp_context *ctx, struct chttp_gzip *gzip,
	void *buffer, size_t buffer_len);
enum chttp_gzip_status chttp_gzip_flate(struct chttp_gzip *gzip, const void *input,
	size_t input_len, void *output, size_t output_len, size_t *written, int finish);
void chttp_gzip_send_chunk(struct chttp_gzip *gzip, struct chttp_addr *addr,
	const void *input, size_t input_len);

#endif /* _CHTTP_GZIP_H_INCLUDED_ */
