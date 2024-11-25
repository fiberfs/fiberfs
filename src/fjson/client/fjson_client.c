/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdio.h>
#include <string.h>

#include "fjson.h"

static void
_usage(int error)
{
	printf("%ssage: fjson_client [-f file | STRING]\n",
		(error ? "ERROR u" : "U"));
}

static int
_json_print(struct fjson_context *ctx)
{
	struct fjson_token *token;

	fjson_context_ok(ctx);

	token = fjson_get_token(ctx, 0);
	fjson_token_ok(token);

	printf("Token: %s length: %u depth: %zu closed: %d\n", fjson_token_name(token->type),
		token->length, ctx->tokens_pos - 2, token->closed);

	if (token->type == FJSON_TOKEN_NUMBER) {
		printf("  dvalue=%lf\n", token->dvalue);
	}

	return 0;
}

int
main(int argc, char **argv)
{
	struct fjson_context json;

	printf("fjson_client\n");

	if (argc < 2) {
		_usage(1);
		return 1;
	}

	if (!strcmp(argv[1], "-f")) {
		if (argc != 3) {
			_usage(1);
			return 1;
		}

		printf("TODO json file: %s\n", argv[2]);

		return 0;
	}

	if (argc != 2) {
		_usage(1);
		return 1;
	}

	printf("json: %s\n", argv[1]);

	fjson_context_init(&json);

	json.callback = &_json_print;
	json.finish = 1;

	fjson_parse(&json, argv[1], strlen(argv[1]));
	fjson_finish(&json);

	printf("Done: %s: %s (%zu)\n", fjson_state_name(json.state),
		json.error ? json.error_msg : "ok", json.position + 1);

	fjson_context_free(&json);

	return 0;
}
