/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdlib.h>

static void
_finish_test(struct chttp_test_context *ctx)
{
	struct chttp_test *test;

	test = chttp_test_convert(ctx);

	chttp_test_ok(test);
	chttp_test_ERROR(test->context.chttp != NULL, "chttp context detected");
	chttp_test_ERROR(test->context.server != NULL, "chttp server detected");

	if (test->fcht) {
		fclose(test->fcht);
		test->fcht = NULL;
	}

	free(test->line_raw);
	chttp_ZERO(test);
}

static void
_init_test(struct chttp_test *test)
{
	assert(test);

	chttp_ZERO(test);

	test->magic = CHTTP_TEST_MAGIC;
	test->verbocity = CHTTP_LOG_VERBOSE;
	test->line_raw_len = 1024;
	test->line_raw = malloc(test->line_raw_len);
	assert(test->line_raw);

	RB_INIT(&test->cmd_tree);
	TAILQ_INIT(&test->finish_list);

	chttp_test_ok(test);
	chttp_test_ok(chttp_test_convert(&test->context));

	chttp_test_register_finish(&test->context, "context", _finish_test);
}

static void
_usage(int error)
{
	printf("%ssage: chttp_test [-q] [-v] [-vv] [-h] [-V] CHT_FILE\n",
		(error ? "ERROR u" : "U"));
}

static void *
_test_run_cht_file(void *arg)
{
	struct chttp_test *test;
	struct chttp_test_cmdentry *cmd_entry;

	test = (struct chttp_test*)arg;
	chttp_test_ok(test);
	assert_zero(test->stopped);

	test->fcht = fopen(test->cht_file, "r");
	chttp_test_ERROR(!test->fcht, "invalid file %s", test->cht_file);

	while (chttp_test_readline(test, 0)) {
		chttp_test_parse_cmd(test);

		chttp_test_ERROR(!test->cmds && strcmp(test->cmd.name, "chttp_test"),
			"test file must begin with chttp_test");

		test->cmds++;

		cmd_entry = chttp_test_cmds_get(test, test->cmd.name);
		chttp_test_ERROR(!cmd_entry || !cmd_entry->is_cmd,
			"command %s not found (line %zu)", test->cmd.name, chttp_test_line_pos(test));
		assert(cmd_entry->cmd_func);

		test->cmd.func = cmd_entry->cmd_func;
		assert_zero(test->cmd.async);

		cmd_entry->cmd_func(&test->context, &test->cmd);

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
	struct chttp_test test;
	int i, ret;

	_init_test(&test);
	chttp_test_cmds_init(&test);

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-q")) {
			test.verbocity = CHTTP_LOG_NONE;
		} else if (!strcmp(argv[i], "-v")) {
			test.verbocity = CHTTP_LOG_VERBOSE;
		} else if (!strcmp(argv[i], "-vv")) {
			test.verbocity = CHTTP_LOG_VERY_VERBOSE;
		} else if (!strcmp(argv[i], "-V")) {
			chttp_test_log(&test.context, CHTTP_LOG_FORCE, "chttp_test %s",
				CHTTP_VERSION);
			return 0;
		} else if (!strcmp(argv[i], "-h")) {
			_usage(0);
			return 0;
		} else if (test.cht_file == NULL) {
			test.cht_file = argv[i];
		} else {
			_usage(1);
			return 1;
		}
	}

	if (!test.cht_file) {
		_usage(1);
		return 1;
	}

	assert_zero(pthread_create(&test.thread, NULL, _test_run_cht_file, &test));

	ret = chttp_test_join_thread(test.thread, &test.stopped, CHTTP_TEST_TIMEOUT_SEC * 1000);
	chttp_test_ERROR(ret, "test timed out after %ds", CHTTP_TEST_TIMEOUT_SEC);

	if (test.error) {
		chttp_test_log(&test.context, CHTTP_LOG_FORCE, "FAILED");
		return 1;
	} else if (test.skip) {
		chttp_test_run_all_finish(&test);
		chttp_test_log(NULL, CHTTP_LOG_FORCE, "SKIPPED");
		return 0;
	}

	chttp_test_run_all_finish(&test);

	chttp_test_log(NULL, CHTTP_LOG_FORCE, "PASSED");

	return 0;
}

void
chttp_test_register_finish(struct chttp_test_context *ctx, const char *name,
    chttp_test_finish_f *func)
{
	struct chttp_test *test;
	struct chttp_test_finish *finish;

	test = chttp_test_convert(ctx);
	assert(name && *name);

	TAILQ_FOREACH(finish, &test->finish_list, entry) {
		assert(finish->magic == CHTTP_TEST_FINISH_MAGIC);
		chttp_test_ERROR(!strcmp(finish->name, name),
			"cannot register the same finish name twice");
		chttp_test_ERROR(finish->func == func,
			"cannot register the same finish function twice");
	}

	finish = malloc(sizeof(*finish));
	assert(finish);

	chttp_ZERO(finish);

	finish->magic = CHTTP_TEST_FINISH_MAGIC;
	finish->name = name;
	finish->func = func;

	TAILQ_INSERT_HEAD(&test->finish_list, finish, entry);
}

void
chttp_test_run_finish(struct chttp_test_context *ctx, const char *name)
{
	struct chttp_test *test;
	struct chttp_test_finish *finish, *temp;

	test = chttp_test_convert(ctx);
	assert(name && *name);

	TAILQ_FOREACH_SAFE(finish, &test->finish_list, entry, temp) {
		assert(finish->magic == CHTTP_TEST_FINISH_MAGIC);

		if (strcmp(finish->name, name)) {
			continue;
		}

		TAILQ_REMOVE(&test->finish_list, finish, entry);

		finish->func(&test->context);

		chttp_ZERO(finish);
		free(finish);

		return;
	}

	chttp_test_ERROR(1, "finish task %s not found", name);
}

void
chttp_test_run_all_finish(struct chttp_test *test)
{
	struct chttp_test_finish *finish, *temp;

	chttp_test_ok(test);

	if (test->verbocity == CHTTP_LOG_VERY_VERBOSE) {
		chttp_test_log(&test->context, CHTTP_LOG_NONE, "shutdown");
	}

	TAILQ_FOREACH_SAFE(finish, &test->finish_list, entry, temp) {
		assert(finish->magic == CHTTP_TEST_FINISH_MAGIC);

		TAILQ_REMOVE(&test->finish_list, finish, entry);

		finish->func(&test->context);

		chttp_ZERO(finish);
		free(finish);
	}

	assert(TAILQ_EMPTY(&test->finish_list));
}
