/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "test/fbr_test.h"

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
	fbr_magic_check(ctx->random, _RANDOM_MAGIC);

	fbr_zero(ctx->random);
	free(ctx->random);

	ctx->random = NULL;
}

static void
_random_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	if (!ctx->random) {
		struct fbr_test_random *random = calloc(1, sizeof(*random));
		assert(random);

		random->magic = _RANDOM_MAGIC;
		random->low = 0;
		random->high = INT32_MAX;

		ctx->random = random;

		fbr_test_register_finish(ctx, "random", _random_finish);

		fbr_test_random_seed();
	}

	fbr_magic_check(ctx->random, _RANDOM_MAGIC);
}

void
fbr_cmd_random_range(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_random_init(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	long val = fbr_test_parse_long(cmd->params[0].value);
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
fbr_var_random(struct fbr_test_context *ctx)
{
	_random_init(ctx);

	long rval = fbr_test_gen_random(ctx->random->low, ctx->random->high);

	fbr_bprintf(ctx->random->random_str, "%ld", rval);

	return ctx->random->random_str;
}
