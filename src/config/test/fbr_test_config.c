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

	config = fbr_config_alloc();
	fbr_config_ok(config);
	assert(config->init);
	fbr_config_add(config, "test", 4, "true", 4);
	fbr_config_add(config, "some_path", 9, "a/b/c", 5);
	fbr_config_add(config, "empty", 5, "", 0);
	fbr_config_add(config, "NULL", 4, NULL, 0);

	for (size_t i = 0; i < 1000; i++) {
		char key_buffer[32];
		char value_buffer[128];

		size_t key_len = fbr_bprintf(key_buffer, "key_%zu", i);
		memset(value_buffer, 'a' + (i % 26), sizeof(value_buffer) - 1);
		value_buffer[sizeof(value_buffer) - 1] = '\0';

		fbr_config_add(config, key_buffer, key_len, value_buffer, sizeof(value_buffer) - 1);
	}

	config->init = 0;

	value = fbr_config_get(config, "test");
	assert(value);
	assert_zero(strcmp(value, "true"));

	value = fbr_config_get(config, "some_path");
	assert(value);
	assert_zero(strcmp(value, "a/b/c"));

	value = fbr_config_get(config, "empty");
	assert(value);
	assert_zero(strcmp(value, ""));

	value = fbr_config_get(config, "NULL");
	assert_zero(value);

	value = fbr_config_get(config, "_zzz");
	assert_zero(value);

	for (size_t i = 0; i < 1000; i++) {
		char key_buffer[32];
		char value_buffer[128];

		fbr_bprintf(key_buffer, "key_%zu", i);
		memset(value_buffer, 'a' + (i % 26), sizeof(value_buffer) - 1);
		value_buffer[sizeof(value_buffer) - 1] = '\0';

		value = fbr_config_get(config, key_buffer);
		assert(value);
		assert_zero(strcmp(value, value_buffer));
	}

	fbr_config_free(config);

	fbr_test_logs("test_config_simple passed");
}
