/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

#include "chttp.h"
#include "compress/chttp_gzip.h"

static void
_body_chunk_end(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_BODY);
	assert(ctx->chunked);
	assert_zero(ctx->length);
	chttp_dpage_ok(ctx->dpage_last);

	if (ctx->data_start.dpage) {
		chttp_dpage_ok(ctx->data_start.dpage);

		size_t start = chttp_dpage_ptr_offset(ctx, &ctx->data_start);
		size_t end;
		int error = chttp_header_endline(ctx->dpage_last, start, NULL, &end, 1, NULL);

		if (error > 0) {
			chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);
			return;
		} else if (error < 0) {
			chttp_dpage_shift_full(ctx);
		} else {
			if (end - start != 1) {
				chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);
				return;
			} else {
				end++;

				if (end == ctx->dpage_last->offset) {
					chttp_dpage_ptr_reset(&ctx->data_start);
				} else {
					chttp_dpage_ptr_set(&ctx->data_start,
						ctx->dpage_last, end, 0);
				}

				return;
			}
		}
	} else {
		chttp_dpage_reset_end(ctx);
		chttp_dpage_get(ctx, 2);
		chttp_dpage_ptr_set(&ctx->data_start, ctx->dpage_last,
			ctx->dpage_last->offset, 0);
	}

	chttp_dpage_ok(ctx->data_start.dpage);
	chttp_tcp_read(ctx);

	if (ctx->state == CHTTP_STATE_BODY) {
		_body_chunk_end(ctx);
		return;
	}

	chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);

	return;
}

static void
_body_chunk_start(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_BODY);
	assert(ctx->chunked);
	assert_zero(ctx->length);
	chttp_dpage_ok(ctx->dpage_last);

	if (ctx->data_start.dpage) {
		chttp_dpage_ok(ctx->data_start.dpage);

		size_t start = chttp_dpage_ptr_offset(ctx, &ctx->data_start);
		size_t end;
		int error = chttp_header_endline(ctx->dpage_last, start, NULL, &end, 1, NULL);

		if (error > 0) {
			chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);
			return;
		} else if (error < 0) {
			chttp_dpage_shift_full(ctx);
		} else {
			errno = 0;
			char *len_start = (char*)&ctx->dpage_last->data[start];
			char *len_end;
			ctx->length = strtol(len_start, &len_end, 16);

			if (ctx->length < 0 || ctx->length == LONG_MAX || errno ||
			    len_end == len_start || *len_end != '\r') {
				chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);
				return;
			}

			end++;

			if (end == ctx->dpage_last->offset) {
				chttp_dpage_ptr_reset(&ctx->data_start);
			} else {
				chttp_dpage_ptr_set(&ctx->data_start, ctx->dpage_last, end, 0);
			}

			if (ctx->length == 0) {
				_body_chunk_end(ctx);

				if (ctx->state == CHTTP_STATE_BODY) {
					ctx->state = CHTTP_STATE_IDLE;

					if (ctx->data_start.dpage) {
						ctx->pipeline = 1;
					}
				}
			}

			return;
		}
	} else {
		chttp_dpage_reset_end(ctx);
		chttp_dpage_get(ctx, 5);
		chttp_dpage_ptr_set(&ctx->data_start, ctx->dpage_last,
			ctx->dpage_last->offset, 0);
	}

	chttp_dpage_ok(ctx->data_start.dpage);
	chttp_tcp_read(ctx);

	if (ctx->state == CHTTP_STATE_BODY) {
		_body_chunk_start(ctx);
		return;
	}

	chttp_error(ctx, CHTTP_ERR_RESP_CHUNK);
}

static void
_body_chunk_parse(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	_body_chunk_end(ctx);

	if (ctx->state == CHTTP_STATE_BODY) {
		_body_chunk_start(ctx);
	} else {
		assert(ctx->error);
	}
}

// Note: caller needs to set ctx->pipeline
void
chttp_body_init(struct chttp_context *ctx, enum chttp_request_type type)
{
	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_BODY);
	assert_zero(ctx->chunked);
	assert(type > CHTTP_REQUEST_NONE);

	if (ctx->version == CHTTP_H_VERSION_1_0) {
		ctx->close = 1;
	}

	const char *header = chttp_header_get(ctx, "connection");
	if (header && !strcasecmp(header, "close")) {
		ctx->close = 1;
	} else if (header && !strcasecmp(header, "keep-alive")) {
		// Default, do nothing
	}

	header = chttp_header_get(ctx, "content-encoding");
	if (header && !strcasecmp(header, "gzip")) {
		ctx->gzip = 1;
	} else {
		ctx->gzip = 0;
	}

	switch (ctx->status) {
		case 100:
			if (ctx->want_100) {
				ctx->state = CHTTP_STATE_SENT;
				ctx->want_100 = 0;
				return;
			}
			/* Fallthru */
		case 204:
		case 304:
			ctx->state = CHTTP_STATE_IDLE;
			return;
	}

	if (ctx->is_head) {
		ctx->state = CHTTP_STATE_IDLE;
		return;
	}

	if (ctx->length) {
		chttp_error(ctx, CHTTP_ERR_REQ_BODY);
		return;
	}

	header = chttp_header_get(ctx, "transfer-encoding");
	if (header && !strcasecmp(header, "chunked")) {
		ctx->chunked = 1;
		_body_chunk_start(ctx);
		return;
	}

	header = chttp_header_get(ctx, "content-length");
	if (header) {
		char *len_end;
		errno = 0;
		ctx->length = strtol(header, &len_end, 10);

		if (ctx->length < 0 || ctx->length == LONG_MAX || errno ||
		    len_end == header || *len_end != '\0') {
			chttp_error(ctx, CHTTP_ERR_RESP_LENGTH);
			return;
		}

		if (ctx->length == 0) {
			ctx->state = CHTTP_STATE_IDLE;
		}

		return;
	}

	if (type == CHTTP_REQUEST) {
		ctx->state = CHTTP_STATE_IDLE;
		return;
	}

	if (ctx->close) {
		ctx->length = -1;
		return;
	}

	chttp_error(ctx, CHTTP_ERR_RESP_LENGTH);

	return;
}

size_t
chttp_body_buffered(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_BODY);
	assert_zero(ctx->chunked);
	assert(ctx->length > 0);

	if (ctx->data_start.dpage) {
		chttp_dpage_ok(ctx->data_start.dpage);

		size_t start = chttp_dpage_ptr_offset(ctx, &ctx->data_start);
		size_t size = ctx->dpage_last->offset - start;

		if (size > (size_t)ctx->length) {
			size = ctx->length;
		}

		return size;
	}

	return 0;
}

size_t
chttp_body_read_raw(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	chttp_context_ok(ctx);
	assert(ctx->state >= CHTTP_STATE_BODY);
	assert(buf);

	if (ctx->state >= CHTTP_STATE_IDLE || !buf_len) {
		return 0;
	}

	assert(ctx->length);

	size_t ret_dpage = 0;
	size_t ret = 0;

	if (ctx->data_start.dpage) {
		chttp_dpage_ok(ctx->data_start.dpage);

		size_t start = chttp_dpage_ptr_offset(ctx, &ctx->data_start);

		// Figure out how much data we have left
		ret_dpage = ctx->dpage_last->offset - start;

		if (ctx->length >= 0 && ret_dpage > (size_t)ctx->length) {
			ret_dpage = ctx->length;
		}

		// We can fit everything
		if (ret_dpage <= buf_len) {
			assert(ret_dpage);

			memcpy(buf, chttp_dpage_ptr_convert(ctx, &ctx->data_start), ret_dpage);

			if (start + ret_dpage < ctx->dpage_last->offset) {
				ctx->data_start.offset += ret_dpage;
			} else {
				assert(start + ret_dpage == ctx->dpage_last->offset);
				chttp_dpage_ptr_reset(&ctx->data_start);
			}

			if (ctx->length > 0) {
				assert(ret_dpage <= (size_t)ctx->length);
				ctx->length -= ret_dpage;
			}

			if (ctx->chunked && ctx->length == 0) {
				_body_chunk_parse(ctx);

				if (ctx->error) {
					return 0;
				} else if (ctx->state >= CHTTP_STATE_IDLE) {
					return ret_dpage;
				}
			}

			assert(ctx->state == CHTTP_STATE_BODY);

			buf = (uint8_t*)buf + ret_dpage;
			buf_len -= ret_dpage;

			if (ctx->data_start.dpage) {
				if (!ctx->chunked && ctx->length == 0) {
					ctx->state = CHTTP_STATE_IDLE;
					ctx->pipeline = 1;

					return ret_dpage;
				}

				return ret_dpage + chttp_body_read_raw(ctx, buf, buf_len);
			}
		} else {
			// Not enough room
			memcpy(buf, chttp_dpage_ptr_convert(ctx, &ctx->data_start), buf_len);

			ctx->data_start.offset += buf_len;

			chttp_dpage_ptr_offset(ctx, &ctx->data_start);

			if (ctx->length > 0) {
				assert(buf_len <= (size_t)ctx->length);
				ctx->length -= buf_len;
			}

			assert(ctx->length);

			return buf_len;
		}
	}

	chttp_dpage_reset_end(ctx);

	size_t len = buf_len;

	if (ctx->length >= 0 && len > (size_t)ctx->length) {
		len = ctx->length;
	}

	if (len) {
		ret = chttp_tcp_read_ctx(ctx, buf, len);
		assert(ret <= buf_len);

		if (ctx->error) {
			return 0;
		}
	}

	buf = (uint8_t*)buf + ret;
	buf_len -= ret;

	if (ctx->length > 0) {
		assert(ret <= (size_t)ctx->length);
		ctx->length -= ret;
	}

	if (ctx->state == CHTTP_STATE_CLOSED) {
		if (ctx->length > 0 || ctx->chunked) {
			chttp_error(ctx, CHTTP_ERR_RESP_BODY);
			return 0;
		} else {
			ctx->length = 0;
			return ret + ret_dpage;
		}
	}

	if (ctx->chunked && ctx->length == 0) {
		_body_chunk_parse(ctx);

		if (ctx->error) {
			return 0;
		}
	} else if (ctx->length == 0) {
		ctx->state = CHTTP_STATE_IDLE;
	}

	if (ctx->length) {
		return ret + ret_dpage + chttp_body_read_raw(ctx, buf, buf_len);
	}

	return ret + ret_dpage;
}

size_t
chttp_body_read(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	chttp_context_ok(ctx);
	assert(ctx->state >= CHTTP_STATE_BODY);
	assert(buf);
	assert(buf_len);

	if (ctx->gzip_priv) {
		assert(ctx->gzip);
		return chttp_gzip_read_body(ctx, buf, buf_len);
	}

	return chttp_body_read_raw(ctx, buf, buf_len);
}

void
chttp_body_send(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	chttp_context_ok(ctx);
	assert(ctx->state == CHTTP_STATE_SENT);
	assert(ctx->length > 0);
	assert(buf);
	assert(buf_len);

	if ((size_t)ctx->length < buf_len) {
		chttp_error(ctx, CHTTP_ERR_REQ_BODY);
		return;
	}

	ctx->length -= buf_len;

	chttp_tcp_send(&ctx->addr, buf, buf_len);
	chttp_tcp_error_check(ctx);
}
