/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fjson.h"

#include <stdlib.h>

void
fjson_context_init(struct fjson_context *ctx)
{
	assert(ctx);

	fbr_ZERO(ctx);

	ctx->magic = FJSON_CTX_MAGIC;

	fjson_context_ok(ctx);
}

struct fjson_context *
fjson_context_alloc(void)
{
	struct fjson_context *ctx;

	ctx = malloc(sizeof(*ctx));
	assert(ctx);

	fjson_context_init(ctx);

	ctx->do_free = 1;

	return ctx;
}

void
fjson_context_free(struct fjson_context *ctx)
{
	int do_free;

	fjson_context_ok(ctx);

	do_free = ctx->do_free;

	fbr_ZERO(ctx);

	if (do_free) {
		free(ctx);
	}
}

void
fjson_parse_token(struct fjson_context *ctx, const char *buf)
{
	fjson_context_ok(ctx);

	(void)buf;
}
