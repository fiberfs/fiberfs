/*
 * Copyright (c) 2024-2025 FiberFS
 *
 */

#include "fiberfs.h"

#ifdef FBR_ZLIB

#include "chttp.h"
#include "network/chttp_network.h"
#include "compress/fbr_gzip.h"

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

#endif /* FBR_ZLIB */
