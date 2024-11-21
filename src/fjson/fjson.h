/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FJSON_H_INCLUDED_
#define _FJSON_H_INCLUDED_

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

#define FJSON_MAX_DEPTH			32

enum fjson_state {
	FJSON_STATE_INIT = 0,
	FJSON_STATE_INDEXING,
	FJSON_STATE_NEEDMORE,
	FJSON_STATE_DONE,
	FJSON_STATE_ERROR,
	FJSON_STATE_ERROR_BADJSON,
	FJSON_STATE_ERROR_TOODEEP,
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
typedef int (fjson_parse_f)(struct fjson_context *);

struct fjson_token {
	unsigned int			magic;
#define FJSON_TOKEN_MAGIC		0x49E9C05D

	enum fjson_token_type		type;

	uint32_t			length;

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

	struct fjson_token		tokens[FJSON_MAX_DEPTH];
	size_t				tokens_pos;

	fjson_parse_f			*callback;
};

void fjson_context_init(struct fjson_context *ctx);
void fjson_parse(struct fjson_context *ctx, const char *buf, size_t buf_len);
struct fjson_context *fjson_context_alloc(void);
struct fjson_token *fjson_get_token(struct fjson_context *ctx, size_t depth);
void fjson_context_free(struct fjson_context *ctx);

const char *fjson_token_name(enum fjson_token_type type);
const char *fjson_state_name(enum fjson_state state);

#define fjson_context_ok(ctx)						\
	do {								\
		assert(ctx);						\
		assert((ctx)->magic == FJSON_CTX_MAGIC);		\
	} while (0)
#define fjson_token_ok(token)						\
	do {								\
		assert(token);						\
		assert((token)->magic == FJSON_TOKEN_MAGIC);		\
	} while (0)

#endif /* _FJSON_H_INCLUDED_ */
