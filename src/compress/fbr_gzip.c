/*
 * Copyright (c) 2024-2025 FiberFS
 *
 */

#include "fiberfs.h"
#include "chttp.h"
#include "fbr_gzip.h"
#include "gzip_zlib.h"

int
fbr_gzip_enabled(void)
{
#ifdef FBR_ZLIB
	return 1;
#else
	return 0;
#endif
}

void
fbr_gzip_inflate_init(struct fbr_gzip *gzip)
{
#ifdef FBR_ZLIB
	fbr_zlib_inflate_init(gzip);
#else
	(void)gzip;
	fbr_ABORT("gzip not configured");
#endif
}

void
fbr_gzip_deflate_init(struct fbr_gzip *gzip)
{
#ifdef FBR_ZLIB
	fbr_zlib_deflate_init(gzip);
#else
	(void)gzip;
	fbr_ABORT("gzip not configured");
#endif
}

struct fbr_gzip *
fbr_gzip_inflate_alloc(void)
{
#ifdef FBR_ZLIB
	return fbr_zlib_alloc(FBR_ZLIB_INFLATE);
#else
	fbr_ABORT("gzip not configured");
	return NULL;
#endif
}

struct fbr_gzip *
fbr_gzip_deflate_alloc(void)
{
#ifdef FBR_ZLIB
	return fbr_zlib_alloc(FBR_ZLIB_DEFLATE);
#else
	fbr_ABORT("gzip not configured");
	return NULL;
#endif
}

void
fbr_gzip_flate(struct fbr_gzip *gzip, const void *input, size_t input_len, void *output,
    size_t output_len, size_t *written, int finish_deflate)
{
#ifdef FBR_ZLIB
	gzip->status = fbr_zlib_flate(gzip, input, input_len, output, output_len, written,
		finish_deflate);
	return;
#else
	(void)gzip;
	(void)input;
	(void)input_len;
	(void)output;
	(void)output_len;
	(void)written;
	(void)finish_deflate;
	fbr_ABORT("gzip not configured");
	return;
#endif
}

void
fbr_gzip_free(void *gzip_priv)
{
#ifdef FBR_ZLIB
	fbr_zlib_free(gzip_priv);
#else
	(void)gzip_priv;
	fbr_ABORT("gzip not configured");
#endif
}

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
