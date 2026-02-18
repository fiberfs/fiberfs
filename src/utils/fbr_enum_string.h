/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#undef FBR_ENUM_NAME
#undef FBR_ENUM_VALUES
#undef FBR_ENUM_VALUES_INIT
#undef FBR_ENUM_END

#define FBR_ENUM_NAME(name) \
	const char * name##_string(enum name value) { \
		switch(value) {
#define FBR_ENUM_VALUES(value, str)		case value: return str;
#define FBR_ENUM_VALUES_INIT(value, str, init)	FBR_ENUM_VALUES(value, str)
#define FBR_ENUM_END(error_str)			default: return error_str; }}
