/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include "fiberfs.h"
#include "test/fbr_test.h"

#define _TEST_ENUM1						\
	FBR_ENUM_NAME(_test_enum1)				\
		FBR_ENUM_VALUE(_test_val1)			\
		FBR_ENUM_VALUE(_test_val2)			\
		FBR_ENUM_VALUE(_test_val3)			\
		FBR_ENUM_VALUE(_test_val4)			\
	FBR_ENUM_END("_test_error")

#define _TEST_ENUM2						\
	FBR_ENUM_NAMES(_test_enum2, _enum2_name)		\
		FBR_ENUM_VALUES(_t2_red, "Red")			\
		FBR_ENUM_VALUES_INIT(_t2_blue, "Blue", 7)	\
		FBR_ENUM_VALUE(_t3_green)			\
		FBR_ENUM_VALUE_INIT(_t4_black, 17)		\
	FBR_ENUM_END(NULL)

#include "utils/fbr_enum_define.h"
_TEST_ENUM1
_TEST_ENUM2

#include "utils/fbr_enum_string_declare.h"
static _TEST_ENUM1
static _TEST_ENUM2

void
fbr_cmd_test_enum(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	int unknown = -1;

	enum _test_enum1 e1 = _test_val3;
	enum _test_enum1 *e2 = (enum _test_enum1*)&unknown;

	assert_zero(strcmp(_test_enum1_string(e1), "_test_val3"));
	assert_zero(strcmp(_test_enum1_string(_test_val1), "_test_val1"));
	assert_zero(strcmp(_test_enum1_string(*e2), "_test_error"));

	enum _test_enum2 t2 = _t2_blue;
	assert(t2 == 7)
	assert(_t4_black == 17)
	assert_zero(strcmp(_enum2_name(_t2_red), "Red"));
	assert_zero(strcmp(_enum2_name(t2), "Blue"));
	assert_zero(strcmp(_enum2_name(_t3_green), "_t3_green"));
	assert_zero(strcmp(_enum2_name(17), "_t4_black"));
	assert_zero(_enum2_name(25));

	fbr_test_logs("test_enum passed");
}

#include "utils/fbr_enum_string.h"
static _TEST_ENUM1
static _TEST_ENUM2
