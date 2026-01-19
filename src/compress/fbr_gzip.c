/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_gzip.h"
#include "fbr_gzip_zlib.h"

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
