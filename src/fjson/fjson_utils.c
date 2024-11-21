/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fjson.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

const char *
fjson_token_name(enum fjson_token_type type)
{
	switch (type) {
		case FJSON_TOKEN_UNDEF:
			return "_UNDEFINED";
		case FJSON_TOKEN_ROOT:
			return "_ROOT";
		case FJSON_TOKEN_OBJECT:
			return "OBJECT";
		case FJSON_TOKEN_ARRAY:
			return "ARRAY";
		case FJSON_TOKEN_LABEL:
			return "LABEL";
		case FJSON_TOKEN_STRING:
			return "STRING";
		case FJSON_TOKEN_NUMBER:
			return "NUMBER";
		case FJSON_TOKEN_TRUE:
			return "TRUE";
		case FJSON_TOKEN_FALSE:
			return "FALSE";
		case FJSON_TOKEN_NULL:
			return "NULL";
	}

	return "_ERROR";
}

const char *
fjson_state_name(enum fjson_state state)
{
	switch (state) {
		case FJSON_STATE_INIT:
			return "INIT";
		case FJSON_STATE_INDEXING:
			return "INDEXING";
		case FJSON_STATE_NEEDMORE:
			return "NEEDMORE";
		case FJSON_STATE_DONE:
			return "DONE";
		case FJSON_STATE_ERROR:
			return "ERROR";
		case FJSON_STATE_ERROR_JSON:
			return "ERROR_JSON";
		case FJSON_STATE_ERROR_SIZE:
			return "ERROR_SIZE";
		case FJSON_STATE_ERROR_CALLBACK:
			return "ERROR_CALLBACK";
	}

	return "ERROR_BADSTATE";
}

void __fbr_attr_printf_p(6)
fjson_do_assert(int cond, const char *function, const char *file, int line, int assert,
    const char *fmt, ...)
{
	va_list ap;

	if (cond) {
		return;
	}

	fprintf(stderr, "%s:%d %s(): %s\n", file, line, function,
		assert ? "Assertion failed" : "Aborted");

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	printf("\n");

	abort();
}
