/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fjson.h"
#include "test/fbr_test.h"

void
fjson_cmd_json_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fjson_context fjson;

	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_unescape(&cmd->params[0]);

	fjson_context_init(&fjson);

	fjson_parse(&fjson, cmd->params[0].value, cmd->params[0].len);
	fjson_finish(&fjson);

	fbr_test_ERROR(fjson.error, "fjson error %s: %s", fjson_state_name(fjson.state),
		fjson.error_msg);

	fjson_context_free(&fjson);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "json_test passed %s",
		cmd->params[0].value);
}

void
fjson_cmd_json_dynamic(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fjson_context *fjson;

	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_unescape(&cmd->params[0]);

	fjson = fjson_context_alloc();

	fjson_parse(fjson, cmd->params[0].value, cmd->params[0].len);
	fjson_finish(fjson);

	fbr_test_ERROR(fjson->error, "fjson error %s: %s", fjson_state_name(fjson->state),
		fjson->error_msg);

	fjson_context_free(fjson);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "json_test passed %s",
		cmd->params[0].value);
}

void
fjson_cmd_json_fail(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fjson_context fjson;

	fbr_test_context_ok(ctx);
	fbr_test_ERROR(cmd->param_count != 1, "Need a single parameter");

	fbr_test_unescape(&cmd->params[0]);

	fjson_context_init(&fjson);

	fjson_parse(&fjson, cmd->params[0].value, cmd->params[0].len);
	fjson_finish(&fjson);

	fbr_test_ERROR(!fjson.error, "fjson error: valid json %s", fjson_state_name(fjson.state));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fjson error %s: %s", fjson_state_name(fjson.state),
		fjson.error_msg);

	fjson_context_free(&fjson);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "json_fail passed %s",
		cmd->params[0].value);
}

void
fjson_cmd_json_multi(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fjson_context fjson;
	char buf[1024];
	size_t i, pos, len;

	fbr_test_context_ok(ctx);
	fbr_test_ERROR(!cmd->param_count, "Need a single parameter");

	fjson_context_init(&fjson);

	pos = 0;

	for (i = 0; i < cmd->param_count; i++) {
		fbr_test_unescape(&cmd->params[i]);
		fbr_test_ERROR(cmd->params[i].len >= sizeof(buf) - pos, "Out of buffer");

		memcpy(buf + pos, cmd->params[i].value, cmd->params[i].len + 1);

		fbr_test_log(ctx, FBR_LOG_VERBOSE, "json_multi: '%s' => '%s'",
			cmd->params[i].value, buf);

		len = pos + cmd->params[i].len;

		fjson_parse(&fjson, buf, len);

		fbr_test_log(ctx, FBR_LOG_VERBOSE, "  pos: %zu len: %zu position: %zu state: %s",
			fjson.pos, len, fjson.position, fjson_state_name(fjson.state));

		fbr_test_ERROR(fjson.error, "fjson error %s: %s", fjson_state_name(fjson.state),
			fjson.error_msg);

		pos = fjson_shift(&fjson, buf, len);
		buf[pos] = '\0';

		fbr_test_log(ctx, FBR_LOG_VERBOSE, "  shift pos: %zu '%s'", pos, buf);
	}

	fjson_finish(&fjson);

	fbr_test_ERROR(fjson.error, "fjson error %s: %s", fjson_state_name(fjson.state),
		fjson.error_msg);

	fjson_context_free(&fjson);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "json_multi passed %zu",
		cmd->param_count);
}
