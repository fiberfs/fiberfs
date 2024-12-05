/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fjson.h"
#include "test/fbr_test.h"

#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

static int
_json_print(struct fjson_context *fjson, void *priv)
{
	struct fbr_test_context *ctx;
	struct fjson_token *token;

	fjson_context_ok(fjson);

	ctx = (struct fbr_test_context*)priv;
	fbr_test_context_ok(ctx);

	token = fjson_get_token(fjson, 0);
	fjson_token_ok(token);

	fbr_test_log(ctx, FBR_LOG_VERBOSE,
		"Token: %s length: %u depth: %zu sep: %d closed: %d",
		fjson_token_name(token->type), token->length, fjson->tokens_pos - 2,
		token->seperated, token->closed);

	if (token->type == FJSON_TOKEN_NUMBER) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "  dvalue=%lf", token->dvalue);
	} else if (token->type == FJSON_TOKEN_STRING || token->type == FJSON_TOKEN_LABEL) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "  svalue=%.*s:%zu",
			(int)token->svalue_len, token->svalue, token->svalue_len);
	}

	return 0;
}

void
fjson_cmd_json_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fjson_context fjson;

	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_unescape(&cmd->params[0]);

	fjson_context_init(&fjson);

	fjson_parse_final(&fjson, cmd->params[0].value, cmd->params[0].len);

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

	fjson_parse_final(fjson, cmd->params[0].value, cmd->params[0].len);

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

	fjson_parse_final(&fjson, cmd->params[0].value, cmd->params[0].len);

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

		fjson_parse_part(&fjson, buf, len);

		fbr_test_log(ctx, FBR_LOG_VERBOSE, "  pos: %zu len: %zu position: %zu state: %s",
			fjson.pos, len, fjson.position, fjson_state_name(fjson.state));

		fbr_test_ERROR(fjson.error, "fjson error %s: %s", fjson_state_name(fjson.state),
			fjson.error_msg);

		pos = fjson_shift(&fjson, buf, len, sizeof(buf) - 1);
		buf[pos] = '\0';

		fbr_test_log(ctx, FBR_LOG_VERBOSE, "  shift pos: %zu '%s'", pos, buf);
	}

	fjson_parse_final(&fjson, buf, pos);

	fbr_test_ERROR(fjson.error, "fjson error %s: %s", fjson_state_name(fjson.state),
		fjson.error_msg);

	fjson_context_free(&fjson);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "json_multi passed %zu",
		cmd->param_count);
}

static void
_json_file(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd, int fail)
{
	struct fjson_context fjson;
	char buf[4096], path[PATH_MAX + 1], *rpath;
	size_t size, len, pos;
	long val;
	int fd, is_random = 0;

	fbr_test_context_ok(ctx);
	fbr_test_ok(ctx->test);
	fbr_test_ERROR(cmd->param_count < 1, "Need a single parameter");
	fbr_test_ERROR(cmd->param_count > 2, "Too many parameters");

	if (cmd->param_count >= 2) {
		val = fbr_test_parse_long(cmd->params[1].value);
		fbr_test_ERROR(val < 0 || val > (long)sizeof(buf), "Bad size");
		size = (size_t)val;
	} else {
		size = 0;
	}

	if (size <= 0) {
		is_random = 1;
	}

	if (cmd->params[0].value[0] == '/') {
		snprintf(path, sizeof(path), "%s", cmd->params[0].value);
	} else {
		rpath = realpath(ctx->test->test_file, path);
		fbr_test_ERROR(rpath != path, "realpath failed");

		len = strlen(rpath);
		fbr_test_ERROR(!len, "bad path");

		for (pos = len - 1; pos > 0; pos--) {
			if (path[pos] == '/') {
				break;
			}
			path[pos] = '\0';
		}

		fbr_test_ERROR(pos + cmd->params[0].len + 1 > sizeof(path), "path too long");

		rpath = &path[pos + 1];

		snprintf(rpath, sizeof(path) - pos, "%s", cmd->params[0].value);
	}

	fd = open(path, O_RDONLY);
	fbr_test_ERROR(fd < 0, "Cant open %s", path);

	fjson_context_init(&fjson);

	fjson.callback = &_json_print;
	fjson.callback_priv = ctx;
	pos = 0;

	do {
		if (is_random) {
			size = fbr_test_gen_random(1, 25);
		}

		fbr_test_ASSERT(pos < sizeof(buf), "bad pos %zu<%zu", pos, sizeof(buf));
		assert(size + pos <= sizeof(buf));

		len = read(fd, buf + pos, size);

		fbr_test_log(ctx, FBR_LOG_VERBOSE, "read %zu (asked %zu)", len, size);

		fjson_parse_part(&fjson, buf, len + pos);

		pos = fjson_shift(&fjson, buf, len + pos, sizeof(buf));

		if (pos) {
			fbr_test_log(ctx, FBR_LOG_VERBOSE, "shifted %zu", pos);
		}
	} while (len > 0);

	fjson_parse_final(&fjson, buf, pos);

	if (fail) {
		fbr_test_ERROR(!fjson.error, "no fjson error %s", fjson_state_name(fjson.state));

		fbr_test_log(ctx, FBR_LOG_VERBOSE, "fjson error %s: %s",
			fjson_state_name(fjson.state), fjson.error_msg);
	} else {
		fbr_test_ERROR(fjson.error, "fjson error %s: %s", fjson_state_name(fjson.state),
			fjson.error_msg);
	}

	fjson_context_free(&fjson);
	close(fd);
}

void
fjson_cmd_json_file(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_json_file(ctx, cmd, 0);
}

void
fjson_cmd_json_file_fail(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_json_file(ctx, cmd, 1);
}
