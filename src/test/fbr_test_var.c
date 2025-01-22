/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "test/fbr_test.h"

#define _MAX_VARS		5

struct fbr_test_var {
	unsigned int		magic;
#define _VAR_MAGIC		0x951348BB

	char			*vars[_MAX_VARS];
};

static void
_var_finish(struct fbr_test_context *ctx)
{
	size_t i;

	fbr_test_context_ok(ctx);
	assert(ctx->var);
	assert(ctx->var->magic == _VAR_MAGIC);

	for (i = 0; i < _MAX_VARS; i++) {
		if (ctx->var->vars[i]) {
			free(ctx->var->vars[i]);
		}
	}

	fbr_ZERO(ctx->var);
	free(ctx->var);

	ctx->var = NULL;
}

static void
_var_init(struct fbr_test_context *ctx)
{
	struct fbr_test_var *var;

	fbr_test_context_ok(ctx);

	if (!ctx->var) {
		assert(_MAX_VARS == sizeof(ctx->var->vars) / sizeof(*ctx->var->vars));

		var = calloc(1, sizeof(*var));
		assert(var);

		var->magic = _VAR_MAGIC;

		ctx->var = var;

		fbr_test_register_finish(ctx, "var", _var_finish);
	}

	assert(ctx->var->magic == _VAR_MAGIC);
}

static char *
_var_get(struct fbr_test_context *ctx, size_t index)
{
	_var_init(ctx);
	assert(index > 0 && index <= _MAX_VARS);

	index--;

	if (!ctx->var->vars[index]) {
		return "";
	}

	return ctx->var->vars[index];
}

#define _VAR_GET(index)						\
char *								\
fbr_test_var_var##index(struct fbr_test_context *ctx)		\
{								\
	return _var_get(ctx, index);				\
}

_VAR_GET(1)
_VAR_GET(2)
_VAR_GET(3)
_VAR_GET(4)
_VAR_GET(5)

static void
_var_set(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd, size_t index)
{
	size_t len, i;

	_var_init(ctx);
	fbr_test_cmd_ok(cmd);
	assert(index > 0 && index <= _MAX_VARS);

	index--;
	len = 0;

	for (i = 0; i < cmd->param_count; i++) {
		fbr_test_unescape(&cmd->params[i]);
		len += cmd->params[i].len;
	}

	if (ctx->var->vars[index]) {
		free(ctx->var->vars[index]);
		ctx->var->vars[index] = NULL;
	}
	assert_zero(ctx->var->vars[index]);

	if (len == 0) {
		return;
	}

	ctx->var->vars[index] = malloc(len + 1);
	fbr_test_ASSERT(ctx->var->vars[index], "var malloc failed %zu", len);

	len = 0;

	for (i = 0; i < cmd->param_count; i++) {
		memcpy(&ctx->var->vars[index][len], cmd->params[i].value, cmd->params[i].len);
		len += cmd->params[i].len;
	}

	ctx->var->vars[index][len] = '\0';
}

#define _VAR_SET(index)									\
void											\
fbr_test_cmd_set_var##index(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)	\
{											\
	_var_set(ctx, cmd, index);							\
}

_VAR_SET(1)
_VAR_SET(2)
_VAR_SET(3)
_VAR_SET(4)
_VAR_SET(5)
