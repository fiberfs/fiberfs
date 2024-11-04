/*
 * Copyright (c) 2024 chttp
 *
 */

#ifndef _CHTTP_DPAGE_H_INCLUDED_
#define _CHTTP_DPAGE_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

struct chttp_dpage {
	unsigned int			magic;
#define CHTTP_DPAGE_MAGIC		0xE8F61099

	struct chttp_dpage		*next;

	size_t				length;
	size_t				offset;

	unsigned int			free:1;

	uint8_t				data[];
};

#define CHTTP_DPAGE_MIN_SIZE		2048
#define CHTTP_DPAGE_SIZE		(sizeof(struct chttp_dpage) + CHTTP_DPAGE_MIN_SIZE)

struct chttp_dpage_ptr {
	struct chttp_dpage		*dpage;
	size_t				offset;
	size_t				length;
};

struct chttp_context;

size_t chttp_dpage_size(int min);
struct chttp_dpage *chttp_dpage_alloc(size_t dpage_size);
void chttp_dpage_init(struct chttp_dpage *dpage, size_t dpage_size);
void chttp_dpage_reset_all(struct chttp_context *ctx);
void chttp_dpage_reset_end(struct chttp_context *ctx);
struct chttp_dpage *chttp_dpage_get(struct chttp_context *ctx, size_t bytes);
void chttp_dpage_append(struct chttp_context *ctx, const void *buffer, size_t buffer_len);
void chttp_dpage_append_mark(struct chttp_context *ctx, const void *buffer, size_t buffer_len,
	struct chttp_dpage_ptr *dptr);
void chttp_dpage_shift_full(struct chttp_context *ctx);
void chttp_dpage_ptr_set(struct chttp_dpage_ptr *dptr, struct chttp_dpage *dpage,
    size_t offset, size_t len);
void chttp_dpage_ptr_reset(struct chttp_dpage_ptr *dptr);
size_t chttp_dpage_ptr_offset(struct chttp_context *ctx, struct chttp_dpage_ptr *dptr);
uint8_t *chttp_dpage_ptr_convert(struct chttp_context *ctx, struct chttp_dpage_ptr *dptr);
void chttp_dpage_free(struct chttp_dpage *dpage);
extern size_t _DEBUG_CHTTP_DPAGE_MIN_SIZE;

#define chttp_dpage_ok(dpage)						\
	do {								\
		assert(dpage);						\
		assert((dpage)->magic == CHTTP_DPAGE_MAGIC);		\
	} while (0)

#endif /* _CHTTP_DPAGE_H_INCLUDED_ */
