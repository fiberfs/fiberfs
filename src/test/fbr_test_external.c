/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "test/fbr_test.h"

int
fbr_test_can_log(struct fbr_test *test, enum fbr_test_verbocity level)
{
	if (!test) {
		struct fbr_test_context *test_ctx = fbr_test_get_ctx();
		test = fbr_test_convert(test_ctx);
	} else {
		fbr_test_ok(test);
	}

	if (level != FBR_LOG_FORCE && (test->verbocity == FBR_LOG_NONE ||
	    test->verbocity < level)) {
		return 0;
	}

	return 1;
}
