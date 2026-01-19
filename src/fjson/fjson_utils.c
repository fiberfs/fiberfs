/*
 * Copyright (c) 2024-2026 FiberFS LLC
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
