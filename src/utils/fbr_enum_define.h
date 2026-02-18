/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#undef FBR_ENUM_NAME
#undef FBR_ENUM_VALUES
#undef FBR_ENUM_VALUES_INIT
#undef FBR_ENUM_END

#define FBR_ENUM_NAME(name) 			enum name {
#define FBR_ENUM_VALUE(value)			FBR_ENUM_VALUES(value, #value)
#define FBR_ENUM_VALUES(value, str)		value,
#define FBR_ENUM_VALUES_INIT(value, str, init)	value = init,
#define FBR_ENUM_END				};
