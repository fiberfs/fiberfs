/*
 * Copyright (c) 2024-2025 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"

#ifdef FBR_ZLIB

#include "fbr_gzip.h"
#include "fbr_gzip_zlib.h"

void
fbr_zlib_inflate_init(struct fbr_zlib *zlib)
{
	assert(zlib);

	fbr_ZERO(zlib);

	zlib->magic = FBR_ZLIB_MAGIC;
	zlib->type = FBR_ZLIB_INFLATE;

	zlib->zs.zalloc = Z_NULL;
	zlib->zs.zfree = Z_NULL;
	zlib->zs.next_in = Z_NULL;
	zlib->zs.avail_in = 0;
	zlib->zs.opaque = Z_NULL;

	int ret = inflateInit2(&zlib->zs, FBR_ZLIB_WINDOW_BITS);
	assert(ret == Z_OK);

	fbr_zlib_ok(zlib);
}

void
fbr_zlib_deflate_init(struct fbr_zlib *zlib)
{
	assert(zlib);

	fbr_ZERO(zlib);

	zlib->magic = FBR_ZLIB_MAGIC;
	zlib->type = FBR_ZLIB_DEFLATE;

	zlib->zs.zalloc = Z_NULL;
	zlib->zs.zfree = Z_NULL;
	zlib->zs.opaque = Z_NULL;

	int ret = deflateInit2(&zlib->zs, FBR_ZLIB_DEFLATE_LEVEL, Z_DEFLATED,
		FBR_ZLIB_WINDOW_BITS, FBR_ZLIB_DEFLATE_MEM, Z_DEFAULT_STRATEGY);
	assert(ret == Z_OK);

	fbr_zlib_ok(zlib);
}

struct fbr_zlib *
fbr_zlib_alloc(enum fbr_zlib_type type)
{
	struct fbr_zlib *zlib;

	zlib = malloc(sizeof(*zlib));
	assert(zlib);

	switch (type) {
		case FBR_ZLIB_INFLATE:
			fbr_zlib_inflate_init(zlib);
			break;
		case FBR_ZLIB_DEFLATE:
			fbr_zlib_deflate_init(zlib);
			break;
		case FBR_ZLIB_NONE:
			fbr_ABORT("invalid fbr_zlib_type");
			return NULL;

	}

	fbr_zlib_ok(zlib);

	zlib->do_free = 1;

	return zlib;
}

int
fbr_zlib_flate(struct fbr_zlib *zlib, const unsigned char *input, size_t input_len,
    unsigned char *output, size_t output_len, size_t *written, int finish_deflate)
{
	fbr_zlib_ok(zlib);
	assert(output);
	assert(output_len);
	assert(written);

	*written = 0;

	if (zlib->zstate == Z_STREAM_END) {
		if (input) {
			return FBR_GZIP_ERROR;
		}
		return FBR_GZIP_DONE;
	} else if (zlib->zstate == Z_BUF_ERROR) {
		if (output_len <= zlib->zs.avail_out && !input) {
			return FBR_GZIP_ERROR;
		}
	} else if (zlib->zstate != Z_OK) {
		return FBR_GZIP_ERROR;
	}

	if (input) {
		assert(input_len);
		assert_zero(zlib->zs.avail_in);
		zlib->zs.next_in = input;
		zlib->zs.avail_in = input_len;
	} else {
		assert(zlib->zs.next_in);
	}

	zlib->zs.next_out = output;
	zlib->zs.avail_out = output_len;

	switch (zlib->type)
	{
		case FBR_ZLIB_INFLATE:
			assert_zero(finish_deflate);
			zlib->zstate = inflate(&zlib->zs, Z_NO_FLUSH);
			break;
		case FBR_ZLIB_DEFLATE:
			zlib->zstate = deflate(&zlib->zs, finish_deflate ? Z_FINISH : Z_NO_FLUSH);
			break;
		default:
			fbr_ABORT("bad zlib flate type");
			return FBR_GZIP_ERROR;
	}

	assert(zlib->zs.avail_out <= output_len);
	*written = output_len - zlib->zs.avail_out;

	if (*written == output_len) {
		assert_zero(zlib->zs.avail_out);

		return FBR_GZIP_MORE_BUFFER;
	}

	assert(*written < output_len);
	assert(zlib->zs.avail_out);

	switch (zlib->zstate)
	{
		case Z_BUF_ERROR:
			if (zlib->zs.avail_in) {
				return FBR_GZIP_MORE_BUFFER;
			}

			return FBR_GZIP_DONE;
		case Z_OK:
		case Z_STREAM_END:
			if(zlib->zs.avail_in) {
				return FBR_GZIP_ERROR;
			}

			return FBR_GZIP_DONE;
		default:
			break;
	}

	return FBR_GZIP_ERROR;
}

void
fbr_zlib_free(struct fbr_zlib *zlib)
{
	int ret, do_free;

	fbr_zlib_ok(zlib);

	do_free = zlib->do_free;

	switch (zlib->type) {
		case FBR_ZLIB_INFLATE:
			ret = inflateEnd(&zlib->zs);
			assert(ret == Z_OK);
			break;
		case FBR_ZLIB_DEFLATE:
			ret = deflateEnd(&zlib->zs);
			assert(ret == Z_OK);
			break;
		case FBR_ZLIB_NONE:
			break;
	}

	fbr_ZERO(zlib);

	if (do_free) {
		free(zlib);
	}
}

#endif /* FBR_ZLIB */
