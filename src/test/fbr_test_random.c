/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "test/fbr_test.h"

#include <stdlib.h>

struct fbr_test_random {
	unsigned int				magic;
#define _RANDOM_MAGIC				0x2E0D1FD1

	long					low;
	long					high;

	char					random_str[64];
};

static void
_random_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	assert(ctx->random);
	assert(ctx->random->magic == _RANDOM_MAGIC);

	fbr_ZERO(ctx->random);
	free(ctx->random);

	ctx->random = NULL;
}

static void
_random_init(struct fbr_test_context *ctx)
{
	struct fbr_test_random *random;

	fbr_test_context_ok(ctx);

	if (!ctx->random) {
		random = calloc(1, sizeof(*random));
		assert(random);

		random->magic = _RANDOM_MAGIC;
		random->low = 0;
		random->high = INT32_MAX;

		ctx->random = random;

		fbr_test_register_finish(ctx, "random", _random_finish);

		fbr_test_random_seed();
	}

	assert(ctx->random->magic == _RANDOM_MAGIC);
}

void
fbr_test_cmd_random_range(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	long val;

	_random_init(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	val = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(val < 0, "invalid random range");

	ctx->random->low = val;

	val = fbr_test_parse_long(cmd->params[1].value);
	fbr_test_ERROR(val < 0, "invalid random range");
	fbr_test_ERROR(ctx->random->low > val, "low is greater than high");

	ctx->random->high = val;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "random range %ld to %ld", ctx->random->low,
		ctx->random->high);
}

char *
fbr_test_var_random(struct fbr_test_context *ctx)
{
	long rval;
	int ret;

	_random_init(ctx);

	rval = fbr_test_gen_random(ctx->random->low, ctx->random->high);

	ret = snprintf(ctx->random->random_str, sizeof(ctx->random->random_str), "%ld", rval);
	assert((size_t)ret < sizeof(ctx->random->random_str));

	return ctx->random->random_str;
}
