/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fjson.h"

#include <errno.h>
#include <math.h>
#include <stdlib.h>

struct fjson_token _FJSON_TOKEN_BAD = {
	FJSON_TOKEN_MAGIC,
	FJSON_TOKEN_UNDEF,
	0,
	NULL,
	0,
	0,
	0,
	0
};

static void _check_errors(struct fjson_context *ctx, struct fjson_token *token,
	enum fjson_token_type child);

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

static void
_set_error(struct fjson_context *ctx, enum fjson_state error, const char *msg)
{
	fjson_context_ok(ctx);
	assert(error >= FJSON_STATE_ERROR);

	ctx->error = 1;
	ctx->state = error;

	if (msg) {
		ctx->error_msg = msg;
	}
}

static inline struct fjson_token *
_bad_token(void)
{
	assert(_FJSON_TOKEN_BAD.type == FJSON_TOKEN_UNDEF);
	assert_zero(_FJSON_TOKEN_BAD.length);
	return &_FJSON_TOKEN_BAD;
}

static void
_callback(struct fjson_context *ctx)
{
	int ret;

	fjson_context_ok(ctx);

	if (ctx->callback) {
		ret = ctx->callback(ctx, ctx->callback_priv);

		if (ret) {
			_set_error(ctx, FJSON_STATE_ERROR_CALLBACK, NULL);
		}
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

static void
_close_token(struct fjson_context *ctx, struct fjson_token *token, int callback)
{
	fjson_context_ok(ctx);
	fjson_token_ok(token);

	token->closed = 1;

	_check_errors(ctx, token, FJSON_TOKEN_UNDEF);

	if (ctx->error) {
		return;
	}

	if (callback) {
		_callback(ctx);
	}

	_pop_token(ctx);
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

static struct fjson_token *
_alloc_next_token(struct fjson_context *ctx, enum fjson_token_type type)
{
	struct fjson_token *token;

	fjson_context_ok(ctx);
	assert(ctx->state == FJSON_STATE_INDEXING);
	assert(ctx->tokens_pos <= FJSON_MAX_DEPTH);

	if (ctx->tokens_pos == FJSON_MAX_DEPTH) {
		_set_error(ctx, FJSON_STATE_ERROR_SIZE, "too deep");
		return _bad_token();
	}

	if (ctx->tokens_pos) {
		token = &ctx->tokens[ctx->tokens_pos - 1];
		fjson_token_ok(token);

		token->length++;

		if(!token->length) {
			_set_error(ctx, FJSON_STATE_ERROR_SIZE, "length too long");
			return _bad_token();
		}

		_check_errors(ctx, token, type);

		if (ctx->error) {
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

static size_t
_count_escapes(const char *buf, size_t pos)
{
	size_t count = 0;

	assert(buf);

	while (count <= pos && buf[pos - count] == '\\') {
		count++;
	}

	return count;
}

static void
_parse_string(struct fjson_context *ctx, const char *buf, size_t buf_len)
{
	struct fjson_token *token;
	int is_valid, is_label;
	size_t start, count;

	fjson_context_ok(ctx);
	assert(ctx->state == FJSON_STATE_INDEXING);
	assert(ctx->pos < buf_len);
	assert(buf);
	assert(buf_len);

	start = ctx->pos;
	is_valid = 0;
	is_label = 0;

	for (ctx->pos++; ctx->pos < buf_len; ctx->pos++) {
		switch (buf[ctx->pos]) {
		case '\"':
			count = _count_escapes(buf, ctx->pos - 1);

			if (count % 2 != 0) {
				continue;
			}

			is_valid = 1;

			break;
		case '\r':
		case '\n':
		case '\v':
		case '\f':
		case '\0':
			_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad string char");
			return;
		default:
			continue;
		}

		break;
	}

	if (!is_valid) {
		if (ctx->pos == buf_len && !ctx->finish) {
			ctx->state = FJSON_STATE_NEEDMORE;
			ctx->pos = start;

			return;
		}

		_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad string");
		return;
	}

	token = fjson_get_token(ctx, 0);
	fjson_token_ok(token);

	if (token->type == FJSON_TOKEN_OBJECT) {
		is_label = 1;
	}

	token = _alloc_next_token(ctx, is_label ? FJSON_TOKEN_LABEL : FJSON_TOKEN_STRING);
	fjson_token_ok(token);

	if (ctx->error) {
		return;
	}

	assert(start + 1 <= ctx->pos);

	token->svalue = &buf[start + 1];
	token->svalue_len = ctx->pos - start - 1;

	_callback(ctx);

	if (!is_label) {
		_pop_token(ctx);
	}
}

static void
_parse_double(struct fjson_context *ctx, const char *buf, size_t buf_len)
{
	struct fjson_token *token;
	int has_decimal, has_exponent, has_number;
	size_t start;
	double value;
	char *end;

	fjson_context_ok(ctx);
	assert(ctx->state == FJSON_STATE_INDEXING);
	assert(ctx->pos < buf_len);
	assert(buf);
	assert(buf_len);

	start = ctx->pos;
	has_decimal = 0;
	has_exponent = 0;
	has_number = 1;

	for (ctx->pos++; ctx->pos < buf_len; ctx->pos++) {
		switch (buf[ctx->pos]) {
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
			has_number = 1;
			continue;
		case '.':
			if (has_decimal || has_exponent) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad decimal number");
				break;
			}

			has_decimal = 1;
			has_number = 0;

			continue;
		case 'e':
		case 'E':
			if (has_exponent || !has_number) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad exponent number");
				break;
			}

			has_exponent = 1;
			has_number = 0;

			continue;
		case '+':
		case '-':
			if (!has_exponent || has_number) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad number");
				break;
			}

			continue;
		default:
			break;
		}

		break;
	}

	if (ctx->error) {
		return;
	}

	if (ctx->pos == buf_len && !ctx->finish) {
		ctx->state = FJSON_STATE_NEEDMORE;
		ctx->pos = start;

		return;
	}

	if (!has_number) {
		_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad number");
		return;
	}

	value = strtod(&buf[start], &end);

	if (end != buf + ctx->pos ||
	    (value == HUGE_VAL && errno == ERANGE) ||
	    (value == -HUGE_VAL && errno == ERANGE)) {
		_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad number conversion");
		return;
	}

	token = _alloc_next_token(ctx, FJSON_TOKEN_NUMBER);
	fjson_token_ok(token);

	if (ctx->error) {
		return;
	}

	token->dvalue = value;

	_callback(ctx);

	_pop_token(ctx);
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
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "too many tokens");
				return;
			}

			break;
		case FJSON_TOKEN_OBJECT:
		case FJSON_TOKEN_ARRAY:
			if (token->closed) {
				if (token->seperated) {
					_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad comma");
					return;
				}
				return;
			}

			assert(token->length);

			if (token->type == FJSON_TOKEN_OBJECT && child != FJSON_TOKEN_LABEL) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad object");
				return;
			}
			if (token->length == 1 && token->seperated) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad comma");
				return;
			}
			if (token->length > 1 && !token->seperated) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "missing comma");
				return;
			}

			break;
		case FJSON_TOKEN_LABEL:
			if (token->length != 1) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad label");
				return;
			}
			if (!token->seperated) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "missing seperator");
				return;
			}

			break;
		default:
			fjson_ABORT("Bad token check");
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

	if (buf_len == 0) {
		return;
	}

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

			if (ctx->error) {
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
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad object");
				return;
			}

			if (token->type == FJSON_TOKEN_LABEL) {
				token->seperated = 1;

				_close_token(ctx, token, 0);

				if (ctx->error) {
					return;
				}

				token = fjson_get_token(ctx, 0);

				if (token->type != FJSON_TOKEN_OBJECT) {
					_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad object");
					return;
				}
			}

			assert(token->type == FJSON_TOKEN_OBJECT);

			_close_token(ctx, token, 1);

			if (ctx->error) {
				return;
			}

			continue;
		/* Start of array */
		case '[':
			token = _alloc_next_token(ctx, FJSON_TOKEN_ARRAY);
			fjson_token_ok(token);

			if (ctx->error) {
				return;
			}

			_callback(ctx);

			continue;
		/* End of array */
		case ']':
			token = fjson_get_token(ctx, 0);
			fjson_token_ok(token);

			if (token->type != FJSON_TOKEN_ARRAY) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad array");
				return;
			}

			_close_token(ctx, token, 1);

			if (ctx->error) {
				return;
			}

			continue;
		/* String literal */
		case '\"':
			_parse_string(ctx, buf, buf_len);

			if (ctx->state > FJSON_STATE_INDEXING) {
				return;
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
			_parse_double(ctx, buf, buf_len);

			if (ctx->state > FJSON_STATE_INDEXING) {
				return;
			}

			ctx->pos--;

			continue;
		/* Object key value separator (label only) */
		case ':':
			token = fjson_get_token(ctx, 0);
			fjson_token_ok(token);

			if (token->type != FJSON_TOKEN_LABEL) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad colon");
				return;
			}

			if (token->seperated || token->length > 0) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "too many colons");
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
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad comma");
				return;
			}

			if (token->seperated) {
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "too many commas");
				return;
			}

			token->seperated = 1;

			if (token->type == FJSON_TOKEN_LABEL) {
				_close_token(ctx, token, 0);

				if (ctx->error) {
					return;
				}

				token = fjson_get_token(ctx, 0);

				if (token->type != FJSON_TOKEN_OBJECT) {
					_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad label");
					return;
				}

				assert_zero(token->seperated);

				token->seperated = 1;
			}

			continue;
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
				_set_error(ctx, FJSON_STATE_ERROR_JSON, "bad literal");
				return;
			}

			token = _alloc_next_token(ctx, literal_type);
			fjson_token_ok(token);

			if (ctx->error) {
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
			_set_error(ctx, FJSON_STATE_ERROR_JSON, "invalid char");
			return;
		}
	}

	assert(ctx->state == FJSON_STATE_INDEXING);
}

void
fjson_parse_part(struct fjson_context *ctx, const char *buf, size_t buf_len)
{
	struct fjson_token *token;

	fjson_context_ok(ctx);

	if (ctx->state >= FJSON_STATE_ERROR) {
		ctx->pos = 0;
		return;
	}

	if (ctx->state == FJSON_STATE_INIT) {
		ctx->state = FJSON_STATE_INDEXING;

		assert_zero(ctx->tokens_pos);

		token = _alloc_next_token(ctx, FJSON_TOKEN_ROOT);
		fjson_token_ok(token);
		assert_zero(ctx->error);
	} else {
		assert(ctx->state == FJSON_STATE_NEEDMORE || ctx->state == FJSON_STATE_DONE);
		assert(ctx->tokens_pos);
		ctx->state = FJSON_STATE_INDEXING;
	}

	ctx->pos = 0;

	_parse_tokens(ctx, buf, buf_len);

	ctx->position += ctx->pos;

	if (ctx->state > FJSON_STATE_INDEXING) {
		return;
	}

	assert(ctx->state == FJSON_STATE_INDEXING);
	assert(ctx->pos == buf_len);
	assert(ctx->tokens_pos);
	assert_zero(ctx->error);

	if (ctx->tokens_pos > 1) {
		ctx->state = FJSON_STATE_NEEDMORE;
	} else {
		token = fjson_get_token(ctx, 0);
		assert(token->type == FJSON_TOKEN_ROOT);

		if (token->length == 0) {
			ctx->state = FJSON_STATE_NEEDMORE;
		} else {
			assert(token->length == 1);
			ctx->state = FJSON_STATE_DONE;
		}
	}

	assert(ctx->state >= FJSON_STATE_NEEDMORE);
}

void
fjson_parse_final(struct fjson_context *ctx, const char *buf, size_t buf_len)
{
	fjson_context_ok(ctx);

	ctx->finish = 1;

	fjson_parse_part(ctx, buf, buf_len);

	if (ctx->state == FJSON_STATE_NEEDMORE) {
		_set_error(ctx, FJSON_STATE_ERROR_JSON, "incomplete");
	}

	assert(ctx->state >= FJSON_STATE_DONE);
}

size_t
fjson_shift(struct fjson_context *ctx, char *buf, size_t buf_len, size_t buf_max)
{
	size_t len;

	fjson_context_ok(ctx);
	assert(ctx->pos <= buf_len);
	assert(buf);

	if (ctx->state != FJSON_STATE_NEEDMORE) {
		return 0;
	}

	if (ctx->pos == buf_len) {
		return 0;
	} else if (ctx->pos == 0) {
		if (buf_len == buf_max) {
			_set_error(ctx, FJSON_STATE_ERROR_SIZE, "out of buffer");
		}

		return buf_len;
	}

	len = buf_len - ctx->pos;

	memmove(buf, buf + ctx->pos, len);

	ctx->pos = 0;

	return len;
}
