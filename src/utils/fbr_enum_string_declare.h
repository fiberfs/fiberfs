/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#undef FBR_ENUM_NAMES
#undef FBR_ENUM_VALUES
#undef FBR_ENUM_VALUES_INIT
#undef FBR_ENUM_END

#define FBR_ENUM_NAMES(name, str_name) \
	const char * str_name(enum name value);

#define FBR_ENUM_VALUES(value, str)
#define FBR_ENUM_VALUES_INIT(value, str, init)
#define FBR_ENUM_END(error_str)
