/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fjson.h"
#include "test/fbr_test.h"

void
fjson_cmd_json_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fjson_context *fjson;

	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_unescape(&cmd->params[0]);

	fjson = fjson_context_alloc();

	fjson_parse(fjson, cmd->params[0].value, cmd->params[0].len);

	fjson_context_free(fjson);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "json_test %s",
		cmd->params[0].value);
}
