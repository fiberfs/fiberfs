/*
 * Copyright (c) 2024-2026 FiberFS LLC
 *
 */

#include "fiberfs.h"
#include "chttp.h"
#include "compress/chttp_gzip.h"

void
chttp_gzip_register(struct chttp_context *ctx, struct fbr_gzip *gzip, void *buffer,
    size_t buffer_len)
{
#ifdef FBR_ZLIB
	assert(gzip);
	assert(buffer);
	assert(buffer_len);

	if (gzip->type == FBR_ZLIB_INFLATE) {
		chttp_context_ok(ctx);
		fbr_ASSERT(!ctx->gzip_priv, "gzip already registered");
		fbr_ASSERT(ctx->gzip, "gzip not detected");
		fbr_ASSERT(ctx->state >= CHTTP_STATE_BODY, "bad chttp state");
		fbr_ASSERT(ctx->state < CHTTP_STATE_CLOSED, "bad chttp state");

		if (ctx->state > CHTTP_STATE_BODY) {
			fbr_gzip_free(gzip);
			return;
		}

		chttp_zlib_register(gzip, buffer, buffer_len);

		ctx->gzip_priv = gzip;
	} else if (gzip->type == FBR_ZLIB_DEFLATE) {
		assert_zero(ctx);

		chttp_zlib_register(gzip, buffer, buffer_len);
	} else {
		fbr_ABORT("Bad gzip type");
	}
#else
	(void)ctx;
	(void)gzip;
	(void)buffer;
	(void)buffer_len;
	fbr_ABORT("gzip not configured");
#endif
}

size_t
chttp_gzip_read_body(struct chttp_context *ctx, void *output, size_t output_len)
{
#ifdef FBR_ZLIB
	return chttp_zlib_read_body(ctx, output, output_len);
#else
	(void)ctx;
	(void)output;
	(void)output_len;
	fbr_ABORT("gzip not configured");
	return 0;
#endif
}

void
chttp_gzip_send_chunk(struct fbr_gzip *gzip, struct chttp_addr *addr, const void *input,
    size_t input_len)
{
#ifdef FBR_ZLIB
	chttp_zlib_send_chunk(gzip, addr, input, input_len);
#else
	(void)gzip;
	(void)addr;
	(void)input;
	(void)input_len;
	fbr_ABORT("gzip not configured");
	return;
#endif
}
