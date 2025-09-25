/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"


void
fbr_cmd_cstore_enable_server(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_CSTORE_CONFIG.server = 1;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_enable_server: %d", _CSTORE_CONFIG.server);
}
