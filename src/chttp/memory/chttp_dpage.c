/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "chttp.h"

size_t
chttp_dpage_size(int min)
{
	size_t min_size = fbr_conf_get_ulong("DEBUG_CHTTP_DPAGE_MIN_SIZE", 0);

	if (min) {
		if (min_size) {
			return min_size;
		} else {
			return CHTTP_DPAGE_MIN_SIZE;
		}
	} else {
		if (min_size) {
			return (sizeof(struct chttp_dpage) + min_size);
		} else {
			return CHTTP_DPAGE_SIZE;
		}
	}
}

struct chttp_dpage *
chttp_dpage_alloc(size_t dpage_size)
{
	dpage_size += sizeof(struct chttp_dpage);
	assert(dpage_size > sizeof(struct chttp_dpage));

	struct chttp_dpage *dpage = malloc(dpage_size);
	assert(dpage);

	chttp_dpage_init(dpage, dpage_size);

	dpage->free = 1;

	return dpage;
}

static struct chttp_dpage *
_dpage_alloc_ctx(struct chttp_context *ctx, size_t dpage_size)
{
	struct chttp_dpage *dpage;

	chttp_context_ok(ctx);

	dpage = chttp_dpage_alloc(dpage_size);

	if (!ctx->dpage) {
		ctx->dpage = dpage;
	} else {
		chttp_dpage_ok(ctx->dpage_last);
		assert_zero(ctx->dpage_last->next);

		ctx->dpage_last->next = dpage;
	}

	ctx->dpage_last = dpage;

	return dpage;
}

void
chttp_dpage_init(struct chttp_dpage *dpage, size_t dpage_size)
{
	assert(dpage);
	assert(dpage_size > sizeof(struct chttp_dpage));

	fbr_zero(dpage);

	dpage->magic = CHTTP_DPAGE_MAGIC;
	dpage->length = dpage_size - sizeof(struct chttp_dpage);
}

void
chttp_dpage_reset_all(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	struct chttp_dpage *dpage;

	for (dpage = ctx->dpage; dpage; dpage = dpage->next) {
		chttp_dpage_ok(dpage);
		dpage->offset = 0;
	}

	if (ctx->dpage) {
		ctx->dpage_last = ctx->dpage;
	}

	chttp_dpage_ptr_reset(&ctx->data_start);
	chttp_dpage_ptr_reset(&ctx->data_end);
	chttp_dpage_ptr_reset(&ctx->hostname);
}

void
chttp_dpage_reset_end(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->data_end.dpage);
	assert_zero(ctx->data_start.dpage);

	struct chttp_dpage *dpage = ctx->data_end.dpage;
	dpage->offset = ctx->data_end.offset;
	ctx->dpage_last = dpage;

	for (dpage = dpage->next; dpage; dpage = dpage->next) {
		chttp_dpage_ok(dpage);
		dpage->offset = 0;
	}
}

struct chttp_dpage *
chttp_dpage_get(struct chttp_context *ctx, size_t bytes)
{
	chttp_context_ok(ctx);

	struct chttp_dpage *dpage = ctx->dpage_last;

	while (dpage) {
		chttp_dpage_ok(dpage);
		assert(dpage->offset <= dpage->length);

		if (ctx->dpage_last != dpage) {
			assert_zero(dpage->offset);
			ctx->dpage_last = dpage;
		}

		if (bytes <= (dpage->length - dpage->offset)) {
			return (dpage);
		}

		dpage = dpage->next;
	}

	size_t dpage_size = chttp_dpage_size(1);

	if (bytes >= dpage_size) {
		dpage_size += bytes;
		assert(dpage_size >= bytes);
	}

	dpage = _dpage_alloc_ctx(ctx, dpage_size);
	assert(dpage == ctx->dpage_last);

	return dpage;
}

void
chttp_dpage_append(struct chttp_context *ctx, const void *buffer, size_t buffer_len)
{
	chttp_context_ok(ctx);
	assert(buffer_len < (10 * 1024 * 1024)); // 10MB

	struct chttp_dpage *dpage = chttp_dpage_get(ctx, buffer_len);
	chttp_dpage_ok(dpage);
	assert(buffer_len <= dpage->length);
	assert(dpage->offset + buffer_len <= dpage->length);

	memcpy(&dpage->data[dpage->offset], (uint8_t*)buffer, buffer_len);

	dpage->offset += buffer_len;
}

void
chttp_dpage_append_mark(struct chttp_context *ctx, const void *buffer, size_t buffer_len,
    struct chttp_dpage_ptr *dptr)
{
	chttp_context_ok(ctx);
	assert(dptr);

	struct chttp_dpage *dpage = chttp_dpage_get(ctx, buffer_len);
	chttp_dpage_ok(dpage);

	chttp_dpage_ptr_set(dptr, dpage, dpage->offset, buffer_len);

	chttp_dpage_append(ctx, buffer, buffer_len);

	assert(dptr->dpage == ctx->dpage_last);
}

void
chttp_dpage_shift_full(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->data_start.dpage);

	struct chttp_dpage *dpage = ctx->dpage_last;

	chttp_dpage_ok(dpage);

	if (dpage->offset < dpage->length) {
		return;
	}

	size_t start = chttp_dpage_ptr_offset(ctx, &ctx->data_start);
	size_t leftover_len = dpage->offset - start;

	// Incomplete line
	if (leftover_len) {
		uint8_t *leftover = chttp_dpage_ptr_convert(ctx, &ctx->data_start);
		chttp_dpage_ptr_reset(&ctx->data_start);

		struct chttp_dpage *dpage_new;

		// Try and shift back
		if (ctx->data_end.dpage && ctx->data_end.dpage != dpage && dpage->offset) {
			chttp_dpage_reset_end(ctx);
			dpage_new = chttp_dpage_get(ctx, leftover_len + 1);
		} else {
			// Move over to a new dpage
			dpage_new = chttp_dpage_get(ctx, leftover_len + 1);
			assert(dpage_new != dpage);
			assert_zero(dpage_new->offset);

			dpage->offset -= leftover_len;
		}

		assert(ctx->dpage_last == dpage_new);
		assert(dpage_new->offset + leftover_len < dpage_new->length);

		memmove(&dpage_new->data[dpage_new->offset], leftover, leftover_len);

		chttp_dpage_ptr_set(&ctx->data_start, dpage_new, dpage_new->offset,
			ctx->data_start.length);

		dpage_new->offset += leftover_len;
		dpage = dpage_new;
	}

	// Make sure we have an available dpage
	chttp_dpage_get(ctx, 1);

	if (ctx->dpage_last != dpage) {
		chttp_dpage_ok(ctx->dpage_last);
		assert_zero(ctx->dpage_last->offset);
		assert_zero(leftover_len);

		chttp_dpage_ptr_set(&ctx->data_start, ctx->dpage_last, 0, 0);
	}
}

void
chttp_dpage_ptr_set(struct chttp_dpage_ptr *dptr, struct chttp_dpage *dpage,
    size_t offset, size_t len)
{
	assert(dptr);
	chttp_dpage_ok(dpage);

	dptr->dpage = dpage;
	dptr->offset = offset;
	dptr->length = len;
}

void
chttp_dpage_ptr_reset(struct chttp_dpage_ptr *dptr)
{
	assert(dptr);

	fbr_zero(dptr);
}

size_t
chttp_dpage_ptr_offset(struct chttp_context *ctx, struct chttp_dpage_ptr *dptr)
{
	chttp_context_ok(ctx);
	assert(dptr);
	chttp_dpage_ok(dptr->dpage);
	assert_dev(dptr->dpage == ctx->dpage_last);
	assert_dev(dptr->offset <= dptr->dpage->offset);

	return dptr->offset;
}

uint8_t *
chttp_dpage_ptr_convert(struct chttp_context *ctx, struct chttp_dpage_ptr *dptr)
{
	size_t offset = chttp_dpage_ptr_offset(ctx, dptr);

	return dptr->dpage->data + offset;
}

void
chttp_dpage_free(struct chttp_dpage *dpage)
{
	while (dpage) {
		chttp_dpage_ok(dpage);

		struct chttp_dpage *curr = dpage;
		dpage = curr->next;

		int do_free = curr->free;

		fbr_zero(curr);

		if (do_free) {
			free(curr);
		}
	}
}
