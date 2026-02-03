/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "config/fbr_config.h"

#include "test/fbr_test.h"

void
fbr_cmd_test_config_simple(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_config *config;
	const char *value;
	long lvalue;

	config = fbr_config_alloc();
	fbr_config_ok(config);

	fbr_config_add(config, "test", 4, "true", 4);
	fbr_config_add(config, "some_path", 9, "a/b/c", 5);
	fbr_config_add(config, "empty", 5, "", 0);
	fbr_config_add(config, "NULL", 4, NULL, 0);
	fbr_config_add(config, "long1", 5, "123", 3);
	fbr_config_add(config, "long2", 5, "-123", 4);
	fbr_config_add(config, "long3", 5, "-1", 2);
	fbr_config_add(config, "long4", 5, "-", 1);
	fbr_config_add(config, "long5", 5, "000", 3);
	fbr_config_add(config, "long6", 5, "", 1);

	assert(config->stat_keys == 10);
	assert(config->stat_deleted == 0);

	fbr_config_add(config, "key_42", 6, "zzz", 3);
	fbr_config_add(config, "key_555", 7, "zzz", 3);

	assert(config->stat_keys == 12);
	assert(config->stat_deleted == 0);

	for (size_t i = 0; i < 1000; i++) {
		char key_buffer[32];
		char value_buffer[128];

		size_t key_len = fbr_bprintf(key_buffer, "key_%zu", i);
		memset(value_buffer, 'a' + (i % 26), sizeof(value_buffer) - 1);
		value_buffer[sizeof(value_buffer) - 1] = '\0';

		fbr_config_add(config, key_buffer, key_len, value_buffer, sizeof(value_buffer) - 1);
	}

	assert(config->stat_keys == 1010);
	assert(config->stat_deleted == 2);

	value = fbr_config_get(config, "test", NULL);
	assert(value);
	assert_zero(strcmp(value, "true"));

	value = fbr_config_get(config, "some_path", NULL);
	assert(value);
	assert_zero(strcmp(value, "a/b/c"));

	value = fbr_config_get(config, "empty", NULL);
	assert(value);
	assert_zero(strcmp(value, ""));

	value = fbr_config_get(config, "NULL", "value");
	assert_zero(value);

	value = fbr_config_get(config, "_zzz", NULL);
	assert_zero(value);

	value = fbr_config_get(config, "_zzz2", "def");
	assert(value);
	assert_zero(strcmp(value, "def"));

	lvalue = fbr_config_get_long(config, "long1", 0);
	assert(lvalue == 123);

	lvalue = fbr_config_get_long(config, "long2", 0);
	assert(lvalue == -123);

	lvalue = fbr_config_get_long(config, "long3", 0);
	assert(lvalue == -1);

	lvalue = fbr_config_get_long(config, "long4", 123);
	assert(lvalue == 123);

	lvalue = fbr_config_get_long(config, "long5", 123);
	assert(lvalue == 0);

	lvalue = fbr_config_get_long(config, "long6", 123);
	assert(lvalue == 123);

	for (size_t i = 0; i < 1000; i++) {
		char key_buffer[32];
		char value_buffer[128];

		fbr_bprintf(key_buffer, "key_%zu", i);
		memset(value_buffer, 'a' + (i % 26), sizeof(value_buffer) - 1);
		value_buffer[sizeof(value_buffer) - 1] = '\0';

		value = fbr_config_get(config, key_buffer, NULL);
		assert(value);
		assert_zero(strcmp(value, value_buffer));
	}

	fbr_config_free(config);

	fbr_test_logs("test_config_simple passed");
}

void
fbr_cmd_test_config_thread(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_config *config = fbr_config_alloc();
	fbr_config_ok(config);

	fbr_config_free(config);

	fbr_test_logs("test_config_thread passed");
}
