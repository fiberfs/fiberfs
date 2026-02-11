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
