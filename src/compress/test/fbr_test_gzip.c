/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include "compress/fbr_gzip.h"

#include "test/fbr_test.h"

char *
fbr_var_gzip_enabled(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	if (fbr_gzip_enabled()) {
		return "1";
	} else {
		return "0";
	}
}

void
fbr_cmd_test_gzip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 0);
	assert(fbr_gzip_enabled());

	fbr_test_logs("test_gzip passed");
}
