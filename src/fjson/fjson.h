/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FJSON_H_INCLUDED_
#define _FJSON_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "utils/fbr_assert.h"

#define FJSON_MAX_DEPTH			32

enum fjson_state {
	FJSON_STATE_INIT = 0,
	FJSON_STATE_INDEXING,
	FJSON_STATE_NEEDMORE,
	FJSON_STATE_DONE,
	FJSON_STATE_ERROR,
	FJSON_STATE_ERROR_JSON,
	FJSON_STATE_ERROR_SIZE,
	FJSON_STATE_ERROR_CALLBACK
};

enum fjson_token_type {
	FJSON_TOKEN_UNDEF = 0,
	FJSON_TOKEN_ROOT,
	FJSON_TOKEN_OBJECT,
	FJSON_TOKEN_ARRAY,
	FJSON_TOKEN_LABEL,
	FJSON_TOKEN_STRING,
	FJSON_TOKEN_NUMBER,
	FJSON_TOKEN_TRUE,
	FJSON_TOKEN_FALSE,
	FJSON_TOKEN_NULL
};

struct fjson_context;
typedef int (fjson_parse_f)(struct fjson_context *, void *);

struct fjson_token {
	unsigned int			magic;
#define FJSON_TOKEN_MAGIC		0x49E9C05D

	enum fjson_token_type		type;

	uint32_t			length;

	const char			*svalue;
	size_t				svalue_len;
	double				dvalue;

	unsigned int			closed:1;
	unsigned int			seperated:1;
};

struct fjson_context {
	unsigned int			magic;
#define FJSON_CTX_MAGIC			0x86EC1921

	enum fjson_state		state;

	size_t				position;
	size_t				pos;

	unsigned int			do_free:1;
	unsigned int			error:1;
	unsigned int			finish:1;

	const char			*error_msg;

	struct fjson_token		tokens[FJSON_MAX_DEPTH];
	size_t				tokens_pos;

	fjson_parse_f			*callback;
	void				*callback_priv;
};

void fjson_context_init(struct fjson_context *ctx);
struct fjson_context *fjson_context_alloc(void);
struct fjson_token *fjson_get_token(struct fjson_context *ctx, size_t depth);
void fjson_parse_partial(struct fjson_context *ctx, const char *buf, size_t buf_len);
void fjson_parse(struct fjson_context *ctx, const char *buf, size_t buf_len);
size_t fjson_shift(struct fjson_context *ctx, char *buf, size_t buf_len, size_t buf_max);
void fjson_context_free(struct fjson_context *ctx);

const char *fjson_token_name(enum fjson_token_type type);
const char *fjson_state_name(enum fjson_state state);

#define fjson_context_ok(ctx)					\
{								\
	assert(ctx);						\
	assert((ctx)->magic == FJSON_CTX_MAGIC);		\
}
#define fjson_token_ok(token)					\
{								\
	assert(token);						\
	assert((token)->magic == FJSON_TOKEN_MAGIC);		\
}

#endif /* _FJSON_H_INCLUDED_ */
