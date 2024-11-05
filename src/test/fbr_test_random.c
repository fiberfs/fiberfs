/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/fbr_test.h"

#include <stdlib.h>

struct chttp_test_random {
	unsigned int				magic;
#define _RANDOM_MAGIC				0x2E0D1FD1

	long					low;
	long					high;

	char					random_str[64];
};

static void
_random_finish(struct chttp_test_context *ctx)
{
	assert(ctx);
	assert(ctx->random);
	assert(ctx->random->magic == _RANDOM_MAGIC);

	chttp_ZERO(ctx->random);
	free(ctx->random);

	ctx->random = NULL;
}

static void
_random_init(struct chttp_test_context *ctx)
{
	struct chttp_test_random *random;

	assert(ctx);

	if (!ctx->random) {
		random = malloc(sizeof(*random));
		assert(random);

		chttp_ZERO(random);

		random->magic = _RANDOM_MAGIC;
		random->low = 0;
		random->high = INT32_MAX;

		ctx->random = random;

		fbr_test_register_finish(ctx, "random", _random_finish);

		chttp_test_random_seed();
	}

	assert(ctx->random->magic == _RANDOM_MAGIC);
}

void
chttp_test_cmd_random_range(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	long val;

	_random_init(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	val = chttp_test_parse_long(cmd->params[0].value);
	chttp_test_ERROR(val < 0, "invalid random range");

	ctx->random->low = val;

	val = chttp_test_parse_long(cmd->params[1].value);
	chttp_test_ERROR(val < 0, "invalid random range");
	chttp_test_ERROR(ctx->random->low > val, "low is greater than high");

	ctx->random->high = val;

	chttp_test_log(ctx, FBR_LOG_VERBOSE, "random range %ld to %ld", ctx->random->low,
		ctx->random->high);
}

char *
chttp_test_var_random(struct chttp_test_context *ctx)
{
	long rval;
	int ret;

	_random_init(ctx);

	rval = chttp_test_random(ctx->random->low, ctx->random->high);

	ret = snprintf(ctx->random->random_str, sizeof(ctx->random->random_str), "%ld", rval);
	assert((size_t)ret < sizeof(ctx->random->random_str));

	return ctx->random->random_str;
}
