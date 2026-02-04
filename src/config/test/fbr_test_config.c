/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "config/fbr_config.h"

#include "test/fbr_test.h"

static void
_sys_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	fbr_config_ok(_CONFIG);

	fbr_config_free(_CONFIG);
	assert_zero(_CONFIG);
}

void
fbr_cmd_config_add(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ASSERT(cmd->param_count == 2, "Need 2 parameters");
	fbr_test_ASSERT(cmd->params[0].len, "Need a valid name");

	fbr_conf_add(cmd->params[0].value, cmd->params[0].len, cmd->params[1].value,
		cmd->params[1].len);

	assert(fbr_conf_get(cmd->params[0].value, NULL));

	fbr_test_logs("config_add '%s'='%s'", cmd->params[0].value,
		fbr_conf_get(cmd->params[0].value, NULL));

	fbr_test_register_finish(ctx, "config", _sys_finish);
}

char *
fbr_varf_config(struct fbr_test_context *ctx, struct fbr_test_param *param)
{
	fbr_test_context_ok(ctx);
	assert(param && param->len);

	const char *value = fbr_conf_get(param->value, NULL);

	if (!value) {
		fbr_test_ABORT("config '%s' not found", param->value);
	}

	return (char*)value;
}

static void
_test_config_simple(struct fbr_config *config)
{
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

	const char *value = fbr_config_get(config, "test", NULL);
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

	long lvalue = fbr_config_get_long(config, "long1", 0);
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

	fbr_test_logs("_config_simple done");
}

void
fbr_cmd_test_config_simple(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_config *config = fbr_config_alloc();
	fbr_config_ok(config);

	_test_config_simple(config);

	fbr_config_free(config);

	fbr_test_logs("test_config_simple passed");
}

void
fbr_cmd_test_config_static(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_config_ok(_CONFIG);

	_test_config_simple(_CONFIG);

	fbr_config_free(_CONFIG);
	assert_zero(_CONFIG);

	fbr_test_logs("test_config_static passed");
}

#define _MAX_ITERATIONS		2000
#define _MAX_KEYS		100
#define _MAX_KEY_LEN		2048
#define _THREAD_READERS		6
#define _THREAD_WRITERS		2
size_t _DONE;
size_t _WRITERS;
size_t _ITERATIONS;
size_t _WRITES;
size_t _READS;
size_t _NUMBERS;
size_t _LENGTH;

static void *
_write_thread(void *arg)
{
	assert(arg);

	struct fbr_config *config = arg;
	fbr_config_ok(config);

	fbr_test_logs("*** write thread running");

	fbr_atomic_add(&_WRITERS, 1);

	while (_WRITERS < _THREAD_WRITERS) {
		fbr_test_sleep_ms(1);
	}

	while (_ITERATIONS < _MAX_ITERATIONS) {
		fbr_atomic_add(&_ITERATIONS, 1);

		long key_id = random() % _MAX_KEYS;
		long value_len = random() % _MAX_KEY_LEN;

		char key_name[32];
		char value_buf[_MAX_KEY_LEN];
		assert((size_t)value_len < sizeof(value_buf));

		size_t key_len = fbr_bprintf(key_name, "k_%ld", key_id);

		fbr_test_fill_random((uint8_t*)value_buf, value_len, 1);
		value_buf[value_len] = '\0';
		assert_dev(strlen(value_buf) == (size_t)value_len);

		fbr_config_add(config, key_name, key_len, value_buf, value_len);

		fbr_atomic_add(&_WRITES, 1);
	}

	return NULL;
}

static void *
_read_thread(void *arg)
{
	assert(arg);

	struct fbr_config *config = arg;
	fbr_config_ok(config);

	fbr_test_logs("*** read thread running");

	while (!_DONE) {
		if (fbr_test_is_valgrind() && fbr_test_gen_random(0, 100) == 0) {
			fbr_sleep_ms(0.001);
		}

		long key_id = random() % _MAX_KEYS;
		char key_name[32];
		fbr_bprintf(key_name, "k_%ld", key_id);

		long lvalue = fbr_config_get_long(config, key_name, -1);
		if (lvalue >= 0) {
			fbr_atomic_add(&_NUMBERS, 1);
		}

		const char *value = fbr_config_get(config, key_name, NULL);
		if (!value) {
			continue;
		}

		fbr_atomic_add(&_READS, 1);

		size_t len = strlen(value);
		fbr_atomic_add(&_LENGTH, len);
	}

	return NULL;
}

void
fbr_cmd_test_config_thread(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	struct fbr_config *config = fbr_config_alloc();
	fbr_config_ok(config);

	assert_zero(_DONE);
	assert_zero(_WRITERS);
	assert_zero(_ITERATIONS);
	assert_zero(_WRITES);
	assert_zero(_READS);
	assert_zero(_NUMBERS);

	fbr_test_logs("*** starting threads");

	pthread_t read_threads[_THREAD_READERS];
	for (size_t i = 0; i < fbr_array_len(read_threads); i++) {
		pt_assert(pthread_create(&read_threads[i], NULL, _read_thread, config));
	}

	pthread_t write_threads[_THREAD_WRITERS];
	for (size_t i = 0; i < fbr_array_len(write_threads); i++) {
		pt_assert(pthread_create(&write_threads[i], NULL, _write_thread, config));
	}

	for (size_t i = 0; i < fbr_array_len(write_threads); i++) {
		pt_assert(pthread_join(write_threads[i], NULL));
	}
	assert(_WRITERS == _THREAD_WRITERS);

	fbr_test_logs("*** writing done, signaling readers");

	_DONE = 1;

	for (size_t i = 0; i < fbr_array_len(read_threads); i++) {
		pt_assert(pthread_join(read_threads[i], NULL));
	}

	fbr_test_logs("*** readers done");

	fbr_test_logs("*** reader stats reads: %zu numbers: %zu", _READS, _NUMBERS);
	fbr_test_logs("*** config stats keys: %zu deleted: %zu", config->stat_keys,
		config->stat_deleted);
	assert(config->stat_keys <= 100);
	assert(config->stat_keys + config->stat_deleted == _WRITES);

	fbr_config_free(config);

	fbr_test_logs("test_config_thread passed");
}
