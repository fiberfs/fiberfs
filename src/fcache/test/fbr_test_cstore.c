/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fcache/fbr_cache_store.h"

#include "test/fbr_test.h"

static void
_test_cstore_finish(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);

	fbr_cache_store_free();
}

void
fbr_cmd_cstore_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_cache_store_init();

	fbr_test_register_finish(ctx, "cstore", _test_cstore_finish);
}
