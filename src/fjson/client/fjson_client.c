/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fjson.h"
#include "test/fbr_test.h"

static void
_usage(int error)
{
	printf("%ssage: fjson_client [-f file | STRING]\n",
		(error ? "ERROR u" : "U"));
}

static int
_json_print(struct fjson_context *ctx, void *priv)
{
	struct fjson_token *token;

	fjson_context_ok(ctx);
	assert_zero(priv);

	token = fjson_get_token(ctx, 0);
	fjson_token_ok(token);

	printf("Token: %s length: %u depth: %zu sep: %d closed: %d\n",
		fjson_token_name(token->type), token->length, ctx->tokens_pos - 2,
		token->seperated, token->closed);

	if (token->type == FJSON_TOKEN_NUMBER) {
		printf("  dvalue=%lf\n", token->dvalue);
	} else if (token->type == FJSON_TOKEN_STRING || token->type == FJSON_TOKEN_LABEL) {
		printf("  svalue=%.*s:%zu\n", (int)token->svalue_len, token->svalue,
			token->svalue_len);
	}

	return 0;
}

int
main(int argc, char **argv)
{
	struct fjson_context json;
	char buf[1024];
	int fd, error;
	size_t i, size, pos, len;

	printf("fjson_client\n");

	if (argc < 2) {
		_usage(1);
		return 1;
	}

	fjson_context_init(&json);
	json.callback = &_json_print;

	error = 0;

	if (!strcmp(argv[1], "-f")) {
		if (argc == 2) {
			fd = STDIN_FILENO;
		} else if (argc == 3) {
			printf("json file: %s\n", argv[2]);

			fd = open(argv[2], O_RDONLY);
		} else {
			_usage(1);
			return 1;
		}

		if (fd < 0) {
			printf("bad file\n");
			return 1;
		}

		pos = 0;

		fbr_test_random_seed();

		do {
			size = fbr_test_gen_random(1, sizeof(buf) - pos);
			assert(size + pos <= sizeof(buf));

			len = read(fd, buf + pos, size);

			fjson_parse_partial(&json, buf, len + pos);

			pos = fjson_shift(&json, buf, len + pos, sizeof(buf));

			if (pos) {
				printf("Shifting %zu\n", pos);
			}
		} while (len > 0 && !json.error);

		fjson_parse(&json, buf, pos);

		if (fd != STDIN_FILENO) {
			error = close(fd);

			if (error) {
				printf("bad close()\n");
				return 1;
			}
		}

		if (json.error) {
			printf("fjson error %s: %s\n", fjson_state_name(json.state),
				json.error_msg);

			error = 1;
		}

		fjson_context_free(&json);

		return error;
	}

	if (argc != 2) {
		_usage(1);
		return 1;
	}

	printf("json: %s\n", argv[1]);

	fjson_parse(&json, argv[1], strlen(argv[1]));

	printf("Done: %s: %s\n", fjson_state_name(json.state),
		json.error ? json.error_msg : "ok");

	if (json.error) {
		printf("%s\n", argv[1]);
		for (i = 1; i < json.position; i++) {
			printf(" ");
		}
		printf("^\n");

		error = 1;
	}

	fjson_context_free(&json);

	return error;
}
