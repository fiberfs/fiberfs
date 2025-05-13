/*
 * Copyright (c) 2024-2025 FiberFS
 *
 */

#include "fiberfs.h"
#include "chttp.h"

#ifdef FBR_ZLIB

#include "fbr_gzip.h"
#include "gzip_zlib.h"
#include "network/chttp_network.h"

#include <stdlib.h>
#include <string.h>

#define fbr_zlib_ok(zlib)	fbr_magic_check(zlib, FBR_ZLIB_MAGIC)

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
    unsigned char *output, size_t output_len, size_t *written, int finish)
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
			assert_zero(finish);
			zlib->zstate = inflate(&zlib->zs, Z_NO_FLUSH);
			break;
		case FBR_ZLIB_DEFLATE:
			zlib->zstate = deflate(&zlib->zs, finish ? Z_FINISH : Z_NO_FLUSH);
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

size_t
chttp_zlib_read_body(struct chttp_context *ctx, unsigned char *output, size_t output_len)
{
	struct fbr_zlib *zlib;
	size_t read, written;

	chttp_context_ok(ctx);
	assert(ctx->gzip_priv);
	assert(output);

	if (!output_len) {
		return 0;
	}

	zlib = ctx->gzip_priv;
	assert(zlib->buffer);
	assert(zlib->buffer_len);
	assert(zlib->type == FBR_ZLIB_INFLATE);
	assert(zlib->status <= FBR_GZIP_DONE);

	if (zlib->status == FBR_GZIP_MORE_BUFFER) {
		fbr_gzip_flate(zlib, NULL, 0, output, output_len, &written, 0);

		if (zlib->status >= FBR_GZIP_ERROR) {
			chttp_error(ctx, CHTTP_ERR_GZIP);
			return 0;
		}

		if (zlib->status == FBR_GZIP_MORE_BUFFER) {
			assert(written == output_len);
			return written;
		}

		assert(written < output_len);

		return written + chttp_zlib_read_body(ctx, output + written, output_len - written);
	}

	assert(zlib->status == FBR_GZIP_DONE);

	read = chttp_body_read_raw(ctx, zlib->buffer, zlib->buffer_len);

	if (!read) {
		return 0;
	}

	fbr_gzip_flate(zlib, zlib->buffer, read, output, output_len, &written, 0);

	if (zlib->status >= FBR_GZIP_ERROR) {
		chttp_error(ctx, CHTTP_ERR_GZIP);
		return 0;
	}

	if (zlib->status == FBR_GZIP_MORE_BUFFER) {
		assert(written == output_len);
		return written;
	}

	assert(written < output_len);

	return written + chttp_zlib_read_body(ctx, output + written, output_len - written);
}

void
chttp_zlib_send_chunk(struct fbr_zlib *zlib, struct chttp_addr *addr, const unsigned char *input,
    size_t input_len)
{
	const unsigned char *inbuf;
	size_t inlen, written, max_chunklen, chunklen, chunk_shift;
	int final;

	fbr_zlib_ok(zlib);
	chttp_addr_connected(addr);
	assert(zlib->buffer);
	assert(zlib->buffer_len);

	inbuf = input;
	inlen = input_len;

	if (input) {
		assert(input_len);
		final = 0;
	} else {
		assert_zero(input_len);
		final = 1;
	}

	assert(zlib->status == FBR_GZIP_DONE);

	do {
		max_chunklen = chttp_make_chunk((char*)zlib->buffer, zlib->buffer_len);
		assert(max_chunklen);
		assert(zlib->buffer_len > max_chunklen + 2);

		fbr_gzip_flate(zlib, inbuf, inlen, zlib->buffer + max_chunklen,
			zlib->buffer_len - max_chunklen - 2, &written, final);

		if (zlib->status == FBR_GZIP_ERROR) {
			chttp_tcp_error(addr, CHTTP_ERR_GZIP);
			return;
		}

		if (written > 0) {
			chunklen = chttp_make_chunk((char*)zlib->buffer, written);
			assert(chunklen);
			assert(chunklen <= max_chunklen);

			chunk_shift = max_chunklen - chunklen;
			written += chunklen;

			if (chunk_shift) {
				memmove(zlib->buffer + chunk_shift, zlib->buffer, chunklen);
			}

			zlib->buffer[chunk_shift + written++] = '\r';
			zlib->buffer[chunk_shift + written++] = '\n';

			assert(chunk_shift + written <= zlib->buffer_len);

			chttp_tcp_send(addr, zlib->buffer + chunk_shift, written);

			if (addr->error) {
				return;
			}
		}

		inbuf = NULL;
		inlen = 0;
	} while (zlib->status == FBR_GZIP_MORE_BUFFER);

	assert(zlib->status == FBR_GZIP_DONE);
}

void
chttp_zlib_register(struct fbr_zlib *zlib, unsigned char *buffer, size_t buffer_len)
{
	fbr_zlib_ok(zlib);
	assert(buffer);
	assert(buffer_len);
	assert_zero(zlib->buffer);
	assert_zero(zlib->buffer_len);

	zlib->buffer = buffer;
	zlib->buffer_len = buffer_len;
}

#endif /* FBR_ZLIB */
