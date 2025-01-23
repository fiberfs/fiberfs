/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "test/fbr_test.h"
#include "test/chttp_test_cmds.h"

#include <stdlib.h>

static void
_finish_test(struct fbr_test_context *ctx)
{
	struct fbr_test *test;

	fbr_test_context_ok(ctx);
	assert_zero(ctx->chttp_test);
	test = fbr_test_convert(ctx);
	assert(test->context == ctx);

	fbr_test_ok(test);

	fbr_test_ERROR(ctx->random != NULL, "random detected");

	if (test->ft_file) {
		fclose(test->ft_file);
		test->ft_file = NULL;
	}

	fbr_ZERO(test->context);
	ctx = NULL;

	free(test->context);
	free(test->line_raw);

	fbr_ZERO(test);
}

static void
_init_test(struct fbr_test *test)
{
	assert(test);

	fbr_ZERO(test);

	test->magic = FBR_TEST_MAGIC;
	test->timeout_ms = FBR_TEST_DEFAULT_TIMEOUT_SEC * 1000;
	test->verbocity = FBR_LOG_VERBOSE;
	test->line_raw_len = 1024;
	test->line_raw = malloc(test->line_raw_len);
	assert(test->line_raw);

	test->context = calloc(1, sizeof(*test->context));
	assert(test->context);
	test->context->magic = FBR_TEST_CONTEXT_MAGIC;
	test->context->test = test;

	test->cmd.magic = FBR_TEST_CMD_MAGIC;

	RB_INIT(&test->cmd_tree);
	TAILQ_INIT(&test->finish_list);

	fbr_test_ok(test);
	fbr_test_ok(fbr_test_convert(test->context));
	fbr_test_cmd_ok(&test->cmd);

	fbr_test_register_finish(test->context, "context", _finish_test);

	chttp_test_init(test->context);
}

static void
_usage(int error)
{
	printf("%ssage: fiberfs_test [-q] [-v] [-vv] [-h] [-V] TEST_FILE\n",
		(error ? "ERROR u" : "U"));
}

static void *
_test_run_test_file(void *arg)
{
	struct fbr_test *test;
	struct fbr_test_cmdentry *cmd_entry;

	test = (struct fbr_test*)arg;
	fbr_test_ok(test);
	assert_zero(test->stopped);

	test->ft_file = fopen(test->test_file, "r");
	fbr_test_ERROR(!test->ft_file, "invalid file %s", test->test_file);

	while (fbr_test_readline(test, 0)) {
		fbr_test_parse_cmd(test);

		fbr_test_cmd_ok(&test->cmd);

		fbr_test_ERROR(!test->cmd_count && strcmp(test->cmd.name, "chttp_test") &&
			strcmp(test->cmd.name, "fiber_test"),
			"test file must begin with chttp_test or fiber_test (found: %s)",
			test->cmd.name);

		test->cmd_count++;

		cmd_entry = fbr_test_cmds_get(test, test->cmd.name);
		fbr_test_ERROR(!cmd_entry || !cmd_entry->is_cmd,
			"command %s not found (line %zu)", test->cmd.name,
			fbr_test_line_pos(test));
		assert(cmd_entry->cmd_func);

		test->cmd.func = cmd_entry->cmd_func;
		assert_zero(test->cmd.async);

		fbr_test_ok(test);
		fbr_test_context_ok(test->context);

		cmd_entry->cmd_func(test->context, &test->cmd);

		if (test->error || test->skip) {
			break;
		}
	}

	test->stopped = 1;

	return NULL;
}

int
main(int argc, char **argv)
{
	struct fbr_test test;
	int i, ret, timeout, error, skip;

	_init_test(&test);
	fbr_test_cmds_init(&test);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-q")) {
			test.verbocity = FBR_LOG_NONE;
		} else if (!strcmp(argv[i], "-v")) {
			test.verbocity = FBR_LOG_VERBOSE;
		} else if (!strcmp(argv[i], "-vv")) {
			test.verbocity = FBR_LOG_VERY_VERBOSE;
		} else if (!strcmp(argv[i], "-V")) {
			fbr_test_log(test.context, FBR_LOG_FORCE, "fiberfs_test %s", FIBERFS_VERSION);
			return 0;
		} else if (!strcmp(argv[i], "-h")) {
			_usage(0);
			return 0;
		} else if (test.test_file == NULL) {
			test.test_file = argv[i];
		} else {
			_usage(1);
			return 1;
		}
	}

	if (!test.test_file) {
		_usage(1);
		return 1;
	}

	assert_zero(pthread_create(&test.thread, NULL, _test_run_test_file, &test));

	ret = fbr_test_join_thread(test.thread, &test.stopped, test.timeout_ms);

	timeout = (int)test.timeout_ms / 1000;
	error = test.error;
	skip = test.skip;

	fbr_test_run_all_finish(&test);

	fbr_test_ERROR(ret, "test timed out after %ds", timeout);

	if (error) {
		fbr_test_log(NULL, FBR_LOG_FORCE, "FAILED");
		return 1;
	} else if (skip) {
		fbr_test_log(NULL, FBR_LOG_FORCE, "SKIPPED");
		return 0;
	}

	fbr_test_log(NULL, FBR_LOG_FORCE, "PASSED");

	return 0;
}

void
fbr_test_register_finish(struct fbr_test_context *ctx, const char *name,
    fbr_test_finish_f *func)
{
	struct fbr_test *test;
	struct fbr_test_finish *finish;

	fbr_test_context_ok(ctx);
	test = fbr_test_convert(ctx);
	assert(name && *name);

	TAILQ_FOREACH(finish, &test->finish_list, entry) {
		assert(finish->magic == FBR_TEST_FINISH_MAGIC);
		fbr_test_ERROR(!strcmp(finish->name, name),
			"cannot register the same finish name twice");
		fbr_test_ERROR(finish->func == func,
			"cannot register the same finish function twice");
	}

	finish = calloc(1, sizeof(*finish));
	assert(finish);

	finish->magic = FBR_TEST_FINISH_MAGIC;
	finish->name = name;
	finish->func = func;

	TAILQ_INSERT_HEAD(&test->finish_list, finish, entry);
}

void
fbr_test_run_finish(struct fbr_test_context *ctx, const char *name)
{
	struct fbr_test *test;
	struct fbr_test_finish *finish, *temp;

	fbr_test_context_ok(ctx);
	test = fbr_test_convert(ctx);
	assert(name && *name);

	TAILQ_FOREACH_SAFE(finish, &test->finish_list, entry, temp) {
		assert(finish->magic == FBR_TEST_FINISH_MAGIC);

		if (strcmp(finish->name, name)) {
			continue;
		}

		TAILQ_REMOVE(&test->finish_list, finish, entry);

		finish->func(test->context);

		fbr_ZERO(finish);
		free(finish);

		return;
	}

	fbr_test_ERROR(1, "finish task %s not found", name);
}

void
fbr_test_run_all_finish(struct fbr_test *test)
{
	struct fbr_test_finish *finish, *temp;

	fbr_test_ok(test);

	if (test->verbocity == FBR_LOG_VERY_VERBOSE) {
		fbr_test_log(test->context, FBR_LOG_NONE, "shutdown");
	}

	TAILQ_FOREACH_SAFE(finish, &test->finish_list, entry, temp) {
		assert(finish->magic == FBR_TEST_FINISH_MAGIC);

		TAILQ_REMOVE(&test->finish_list, finish, entry);

		fbr_test_context_ok(test->context);

		finish->func(test->context);

		fbr_ZERO(finish);
		free(finish);
	}

	assert(TAILQ_EMPTY(&test->finish_list));
}
