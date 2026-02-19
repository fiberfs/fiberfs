/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FJSON_H_INCLUDED_
#define _FJSON_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#include "utils/fbr_assert.h"

#define FJSON_MAX_DEPTH			32

#define FJSON_ENUM_STATE 							\
	FBR_ENUM_NAMES(fjson_state, fjson_state_name)				\
		FBR_ENUM_VALUES_INIT(FJSON_STATE_INIT, "INIT", 0)		\
		FBR_ENUM_VALUES(FJSON_STATE_INDEXING, "INDEXING")		\
		FBR_ENUM_VALUES(FJSON_STATE_NEEDMORE, "NEEDMORE")		\
		FBR_ENUM_VALUES(FJSON_STATE_DONE, "DONE")			\
		FBR_ENUM_VALUES(FJSON_STATE_ERROR, "ERROR")			\
		FBR_ENUM_VALUES(FJSON_STATE_ERROR_JSON, "ERROR_JSON")		\
		FBR_ENUM_VALUES(FJSON_STATE_ERROR_SIZE, "ERROR_SIZE")		\
		FBR_ENUM_VALUES(FJSON_STATE_ERROR_CALLBACK, "ERROR_CALLBACK")	\
	FBR_ENUM_END("ERROR_BADSTATE")

#define FJSON_ENUM_TOKEN_TYPE 							\
	FBR_ENUM_NAMES(fjson_token_type, fjson_token_name)			\
		FBR_ENUM_VALUES_INIT(FJSON_TOKEN_UNDEF, "_UNDEFINED", 0)	\
		FBR_ENUM_VALUES(FJSON_TOKEN_ROOT, "_ROOT")			\
		FBR_ENUM_VALUES(FJSON_TOKEN_OBJECT, "OBJECT")			\
		FBR_ENUM_VALUES(FJSON_TOKEN_ARRAY, "ARRAY")			\
		FBR_ENUM_VALUES(FJSON_TOKEN_LABEL, "LABEL")			\
		FBR_ENUM_VALUES(FJSON_TOKEN_STRING, "STRING")			\
		FBR_ENUM_VALUES(FJSON_TOKEN_NUMBER, "NUMBER")			\
		FBR_ENUM_VALUES(FJSON_TOKEN_TRUE, "TRUE")			\
		FBR_ENUM_VALUES(FJSON_TOKEN_FALSE, "FALSE")			\
		FBR_ENUM_VALUES(FJSON_TOKEN_NULL, "NULL")			\
	FBR_ENUM_END("_ERROR")

#include "utils/fbr_enum_define.h"
FJSON_ENUM_STATE
FJSON_ENUM_TOKEN_TYPE

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

#include "utils/fbr_enum_string.h"
static inline FJSON_ENUM_STATE
static inline FJSON_ENUM_TOKEN_TYPE

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
