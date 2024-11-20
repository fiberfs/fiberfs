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

	fjson_parse_token(&json, argv[1]);

	fjson_context_free(&json);

	return 0;
}
