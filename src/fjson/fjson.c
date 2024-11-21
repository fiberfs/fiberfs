/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fjson.h"

#include <stdlib.h>

struct fjson_token _FJSON_TOKEN_BAD = {
	FJSON_TOKEN_MAGIC,
	FJSON_TOKEN_UNDEF,
	0,
	0,
	0
};

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

static inline int
_context_error(struct fjson_context *ctx)
{
	return (ctx->state >= FJSON_STATE_ERROR);
}

static inline struct fjson_token *
_bad_token(void)
{
	assert(_FJSON_TOKEN_BAD.type == FJSON_TOKEN_UNDEF);
	assert_zero(_FJSON_TOKEN_BAD.length);
	return &_FJSON_TOKEN_BAD;
}

// Tokens are checked when a child is allocated or when they are closed
static void
_check_errors(struct fjson_context *ctx, struct fjson_token *token, enum fjson_token_type child)
{
	fjson_context_ok(ctx);
	fjson_token_ok(token);
	assert(child > FJSON_TOKEN_UNDEF || token->closed);

	switch (token->type) {
		case FJSON_TOKEN_ROOT:
			assert_zero(token->closed);
			assert_zero(token->seperated);
			if (token->length > 1) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}

			break;
		case FJSON_TOKEN_OBJECT:
		case FJSON_TOKEN_ARRAY:
			if (token->closed) {
				if (token->seperated) {
					ctx->state = FJSON_STATE_ERROR_BADJSON;
					return;
				}
				return;
			}

			assert(token->length);

			if (token->type == FJSON_TOKEN_OBJECT && child != FJSON_TOKEN_LABEL) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}
			if (token->length == 1 && token->seperated) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}
			if (token->length > 1 && !token->seperated) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}

			break;
		case FJSON_TOKEN_LABEL:
			if (token->length != 1) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}
			if (token->closed && !token->seperated) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}

			break;
		case FJSON_TOKEN_STRING:
		case FJSON_TOKEN_NUMBER:
		case FJSON_TOKEN_TRUE:
		case FJSON_TOKEN_FALSE:
		case FJSON_TOKEN_NULL:
			assert_zero(token->closed);
			assert_zero(token->seperated);
			break;
		case FJSON_TOKEN_UNDEF:
			fjson_ABORT("Bad token check");
	}
}

static void
_pop_token(struct fjson_context *ctx)
{
	struct fjson_token *token;

	fjson_context_ok(ctx);
	assert(ctx->state == FJSON_STATE_INDEXING || ctx->state == FJSON_STATE_ERROR_CALLBACK);
	assert(ctx->tokens_pos <= FJSON_MAX_DEPTH);
	assert(ctx->tokens_pos);

	ctx->tokens_pos--;

	token = &ctx->tokens[ctx->tokens_pos];
	fjson_token_ok(token);

	fbr_ZERO(token);
}

struct fjson_token *
fjson_get_token(struct fjson_context *ctx, size_t depth)
{
	struct fjson_token *token;

	fjson_context_ok(ctx);
	assert(ctx->state == FJSON_STATE_INDEXING);
	assert(ctx->tokens_pos <= FJSON_MAX_DEPTH);

	if (ctx->tokens_pos == 0 || depth >= ctx->tokens_pos) {
		return _bad_token();
	}

	assert(depth < ctx->tokens_pos);

	token = &ctx->tokens[ctx->tokens_pos - 1 - depth];
	assert(token->magic == FJSON_TOKEN_MAGIC);

	return token;
}

// TODO we always add_length?
static struct fjson_token *
_alloc_next_token(struct fjson_context *ctx, enum fjson_token_type type)
{
	struct fjson_token *token;

	fjson_context_ok(ctx);
	assert(ctx->state == FJSON_STATE_INDEXING);
	assert(ctx->tokens_pos <= FJSON_MAX_DEPTH);

	if (ctx->tokens_pos == FJSON_MAX_DEPTH) {
		ctx->state = FJSON_STATE_ERROR_TOODEEP;
		return _bad_token();
	}

	if (ctx->tokens_pos) {
		token = &ctx->tokens[ctx->tokens_pos - 1];
		fjson_token_ok(token);

		token->length++;

		if(!token->length) {
			ctx->state = FJSON_STATE_ERROR_TOODEEP;
			return _bad_token();
		}

		_check_errors(ctx, token, type);

		if (_context_error(ctx)) {
			return _bad_token();
		}

		token->seperated = 0;
	}

	token = &ctx->tokens[ctx->tokens_pos];
	assert_zero(token->magic);

	fbr_ZERO(token);

	token->magic = FJSON_TOKEN_MAGIC;
	token->type = type;

	ctx->tokens_pos++;

	return token;
}

static void
_callback(struct fjson_context *ctx)
{
	int ret;

	fjson_context_ok(ctx);

	if (ctx->callback) {
		ret = ctx->callback(ctx);

		if (ret) {
			ctx->state = FJSON_STATE_ERROR_CALLBACK;
		}
	}
}

static void
_parse_tokens(struct fjson_context *ctx, const char *buf, size_t buf_len)
{
	struct fjson_token *token;
	enum fjson_token_type literal_type;
	const char *literal_value;
	size_t literal_len;

	fjson_context_ok(ctx);
	assert(ctx->state == FJSON_STATE_INDEXING);
	assert(ctx->pos < buf_len);

	assert(buf);
	assert(buf_len);

	literal_value = NULL;

	for (; ctx->pos < buf_len; ctx->pos++) {
		assert(ctx->state == FJSON_STATE_INDEXING);
		switch (buf[ctx->pos]) {
		/* Start of object */
		case '{':
			token = _alloc_next_token(ctx, FJSON_TOKEN_OBJECT);
			fjson_token_ok(token);

			if (_context_error(ctx)) {
				return;
			}

			_callback(ctx);

			continue;
		/* End of object */
		case '}':
			token = fjson_get_token(ctx, 0);
			fjson_token_ok(token);

			if (token->type != FJSON_TOKEN_OBJECT &&
			    token->type != FJSON_TOKEN_LABEL) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}

			if (token->type == FJSON_TOKEN_LABEL) {
				token->closed = 1;

				_check_errors(ctx, token, FJSON_TOKEN_UNDEF);

				if (_context_error(ctx)) {
					return;
				}

				_pop_token(ctx);
				token = fjson_get_token(ctx, 0);

				if (token->type != FJSON_TOKEN_OBJECT) {
					ctx->state = FJSON_STATE_ERROR_BADJSON;
					return;
				}
			}

			assert(token->type == FJSON_TOKEN_OBJECT);

			token->closed = 1;

			_check_errors(ctx, token, FJSON_TOKEN_UNDEF);

			if (_context_error(ctx)) {
				return;
			}

			_callback(ctx);

			_pop_token(ctx);

			continue;
		/* Start of array */
		case '[':
			token = _alloc_next_token(ctx, FJSON_TOKEN_ARRAY);
			fjson_token_ok(token);

			if (_context_error(ctx)) {
				return;
			}

			_callback(ctx);

			continue;
		/* End of array */
		case ']':
			token = fjson_get_token(ctx, 0);
			fjson_token_ok(token);

			if (token->type != FJSON_TOKEN_ARRAY) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}

			token->closed = 1;

			_check_errors(ctx, token, FJSON_TOKEN_UNDEF);

			if (_context_error(ctx)) {
				return;
			}

			_callback(ctx);

			_pop_token(ctx);

			continue;
		/* String literal */
		case '\"':
			ctx->state = FJSON_STATE_ERROR_BADJSON;
			return;
		/* Object key value separator (label only) */
		case ':':
			token = fjson_get_token(ctx, 0);
			fjson_token_ok(token);

			if (token->type != FJSON_TOKEN_LABEL) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}

			token->seperated = 1;

			continue;
		/* Element separator (objects and arrays) */
		case ',':
			token = fjson_get_token(ctx, 0);
			fjson_token_ok(token);

			if (token->type != FJSON_TOKEN_LABEL &&
			    token->type != FJSON_TOKEN_ARRAY) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}

			token->seperated = 1;

			if (token->type == FJSON_TOKEN_LABEL) {
				token->closed = 1;

				_check_errors(ctx, token, FJSON_TOKEN_UNDEF);

				if (_context_error(ctx)) {
					return;
				}

				_pop_token(ctx);
				token = fjson_get_token(ctx, 0);

				if (token->type != FJSON_TOKEN_OBJECT) {
					ctx->state = FJSON_STATE_ERROR_BADJSON;
					return;
				}

				token->seperated = 1;
			}

			continue;
		/* Number */
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case '-':
			ctx->state = FJSON_STATE_ERROR_BADJSON;
			return;
		/* Literal true */
		case 't':
			literal_value = "true";
			literal_type = FJSON_TOKEN_TRUE;
			literal_len = 4;
			goto literal;
		/* Literal false */
		case 'f':
			literal_value = "false";
			literal_type = FJSON_TOKEN_FALSE;
			literal_len = 5;
			goto literal;
		/* Literal null */
		case 'n':
			literal_value = "null";
			literal_type = FJSON_TOKEN_NULL;
			literal_len = 4;
			goto literal;
		literal:
			assert(literal_value);
			assert(literal_type > FJSON_TOKEN_UNDEF);
			assert(literal_len);

			if (buf_len - ctx->pos < literal_len) {
				ctx->state = FJSON_STATE_NEEDMORE;
				return;
			}

			if (strncmp(&buf[ctx->pos], literal_value, literal_len)) {
				ctx->state = FJSON_STATE_ERROR_BADJSON;
				return;
			}

			token = _alloc_next_token(ctx, literal_type);
			fjson_token_ok(token);

			if (_context_error(ctx)) {
				return;
			}

			_callback(ctx);

			_pop_token(ctx);

			ctx->pos += literal_len - 1;

			literal_value = NULL;

			continue;
		/* Whitespace */
		case '\t':
		case '\r':
		case '\n':
		case ' ':
		case '\v':
		case '\f':
			continue;
		/* Invalid json token char */
		default:
			ctx->state = FJSON_STATE_ERROR_BADJSON;
			return;
		}
	}

	assert(ctx->state == FJSON_STATE_INDEXING);
}

void
fjson_parse(struct fjson_context *ctx, const char *buf, size_t buf_len)
{
	struct fjson_token *token;

	fjson_context_ok(ctx);

	if (buf_len == 0 || ctx->state >= FJSON_STATE_ERROR) {
		return;
	}

	if (ctx->state == FJSON_STATE_DONE) {
		ctx->state = FJSON_STATE_ERROR_BADJSON;
		ctx->position++;
		return;
	}

	if (ctx->state == FJSON_STATE_INIT) {
		ctx->state = FJSON_STATE_INDEXING;

		assert_zero(ctx->tokens_pos);

		token = _alloc_next_token(ctx, FJSON_TOKEN_ROOT);
		fjson_token_ok(token);
		assert_zero(_context_error(ctx));
	} else {
		assert(ctx->state == FJSON_STATE_NEEDMORE);
		assert(ctx->tokens_pos);
		ctx->state = FJSON_STATE_INDEXING;
	}

	ctx->pos = 0;

	if (ctx->tokens_pos >= FJSON_MAX_DEPTH) {
		ctx->state = FJSON_STATE_ERROR_TOODEEP;
		ctx->position += ctx->pos;
		return;
	}

	_parse_tokens(ctx, buf, buf_len);

	ctx->position += ctx->pos;

	if (ctx->state > FJSON_STATE_INDEXING) {
		return;
	}

	assert(ctx->pos == buf_len);
	assert(ctx->state == FJSON_STATE_INDEXING);
	assert(ctx->tokens_pos);

	if (ctx->tokens_pos > 1) {
		ctx->state = FJSON_STATE_NEEDMORE;
	} else {
		token = fjson_get_token(ctx, 0);
		assert(token->type == FJSON_TOKEN_ROOT);

		ctx->state = FJSON_STATE_DONE;
	}
}
