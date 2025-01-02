/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"

#include <stdlib.h>

static void
_context_init_size(struct chttp_context *ctx, size_t dpage_size)
{
	explicit_bzero(ctx, CHTTP_CTX_SIZE);

	ctx->magic = CHTTP_CTX_MAGIC;

	if (dpage_size > sizeof(struct chttp_dpage)) {
		ctx->dpage = (struct chttp_dpage*)ctx->_data;
		ctx->dpage_last = ctx->dpage;

		chttp_dpage_init(ctx->dpage, dpage_size);
	}
}

static struct chttp_context *
_context_alloc_size(size_t dpage_size)
{
	struct chttp_context *ctx;

	ctx = malloc(CHTTP_CTX_SIZE + dpage_size);
	assert(ctx);

	_context_init_size(ctx, dpage_size);

	ctx->do_free = 1;

	return ctx;
}

struct chttp_context *
chttp_context_alloc(void)
{
	return _context_alloc_size(chttp_dpage_size(0));
}

void
chttp_context_init(struct chttp_context *ctx)
{
	assert(ctx);

	_context_init_size(ctx, sizeof(ctx->_data));
}

struct chttp_context *
chttp_context_init_buf(void *buffer, size_t buffer_len)
{
	struct chttp_context *ctx;

	assert(buffer);
	assert(buffer_len >= CHTTP_CTX_SIZE);

	ctx = buffer;

	_context_init_size(ctx, buffer_len - CHTTP_CTX_SIZE);

	return ctx;
}

void
chttp_context_reset(struct chttp_context *ctx)
{
	size_t off_start, off_end;

	chttp_context_ok(ctx);

	if (ctx->state < CHTTP_STATE_DONE) {
		chttp_finish(ctx);
	}

	assert(ctx->state >= CHTTP_STATE_DONE);
	assert(ctx->addr.state != CHTTP_ADDR_CONNECTED);
	assert_zero(ctx->addr.tls_priv);
	assert_zero(ctx->gzip_priv);

	chttp_addr_reset(&ctx->addr);

	off_start = offsetof(struct chttp_context, state);
	off_end = offsetof(struct chttp_context, _data);

	memset((char*)ctx + off_start, 0, off_end - off_start);
}

void
chttp_context_free(struct chttp_context *ctx)
{
	int do_free;

	chttp_context_ok(ctx);

	chttp_context_reset(ctx);
	chttp_dpage_free(ctx->dpage);

	do_free = ctx->do_free;

	explicit_bzero(ctx, CHTTP_CTX_SIZE);

	if (do_free) {
		free(ctx);
	}
}
