/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>

#include "test/fbr_test.h"
#include "test/chttp_test_cmds.h"

static struct fbr_test *_TEST;
static int _EXIT;
static int _ERROR;
pthread_mutex_t _FINISH_LOCK;

static void
_finish_test(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	assert_zero(ctx->chttp_test);

	struct fbr_test *test = fbr_test_convert(ctx);
	assert(test->context == ctx);

	fbr_test_ok(test);

	fbr_test_ERROR(ctx->sys != NULL, "sys detected");
	fbr_test_ERROR(ctx->test_fuse != NULL, "test_fuse detected");
	fbr_test_ERROR(ctx->random != NULL, "random detected");
	fbr_test_ERROR(ctx->var != NULL, "var detected");
	fbr_test_ERROR(ctx->shell != NULL, "shell detected");
	fbr_test_ERROR(ctx->chttp_test != NULL, "chttp_test detected");

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
	printf("%ssage: fiberfs_test [-q] [-v] [-vv] [-h] [-k] [-V] TEST_FILE\n",
		(error ? "ERROR u" : "U"));
}

static void *
_test_run_test_file(void *arg)
{
	struct fbr_test *test = (struct fbr_test*)arg;
	fbr_test_ok(test);
	assert_zero(test->stopped);
	assert(fbr_test_is_thread());

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

		struct fbr_test_cmdentry *cmd_entry = fbr_test_cmds_get(test, test->cmd.name);
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
fbr_test_main(int argc, char **argv)
{
	struct fbr_test test;

	fbr_setup_crash_signals();

	_init_test(&test);
	fbr_test_cmds_init(&test);

	pt_assert(pthread_mutex_init(&_FINISH_LOCK, NULL));

	assert_zero(_TEST);
	_TEST = &test;
	fbr_test_ok(_TEST);

	test.prog_name = argv[0];

	for (int i = 1; i < argc; i++) {
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
		} else if (!strcmp(argv[i], "-k")) {
			test.forked = 1;
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

	pt_assert(pthread_create(&test.thread, NULL, _test_run_test_file, &test));
	assert_zero(fbr_test_is_thread());

	int ret = fbr_test_join_thread(test.thread, &test.stopped, &test.timeout_ms);
	fbr_test_ERROR(ret, "test timed out after %ds", (int)test.timeout_ms / 1000);

	int error = test.error;
	int skip = test.skip;
	int forked = test.forked;
	enum fbr_test_verbocity verbosity = test.verbocity;
	assert_zero(_ERROR);

	fbr_test_run_all_finish(&test);

	if (error || _ERROR) {
		if (forked) {
			if (verbosity >= FBR_LOG_VERBOSE) {
				fbr_test_log(NULL, FBR_LOG_NONE, "FAILED");
			}
		} else {
			fbr_test_log(NULL, FBR_LOG_FORCE, "FAILED");
		}
		return 1;
	} else if (skip) {
		if (forked) {
			if (verbosity >= FBR_LOG_VERBOSE) {
				fbr_test_log(NULL, FBR_LOG_NONE, "SKIPPED");
			}
		} else {
			fbr_test_log(NULL, FBR_LOG_FORCE, "SKIPPED");
		}
		return 0;
	}

	if (forked) {
		if (verbosity >= FBR_LOG_VERBOSE) {
			fbr_test_log(NULL, FBR_LOG_NONE, "PASSED");
		}
	} else {
		fbr_test_log(NULL, FBR_LOG_FORCE, "PASSED");
	}

	return 0;
}

int
main(int argc, char **argv)
{
	return fbr_test_main(argc, argv);
}

void
fbr_test_register_finish(struct fbr_test_context *ctx, const char *name,
    fbr_test_finish_f *func)
{
	fbr_test_context_ok(ctx);

	struct fbr_test *test = fbr_test_convert(ctx);
	assert(name && *name);

	struct fbr_test_finish *finish;

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
fbr_test_run_all_finish(struct fbr_test *test)
{
	pt_assert(pthread_mutex_lock(&_FINISH_LOCK));

	if (_EXIT) {
		pt_assert(pthread_mutex_unlock(&_FINISH_LOCK));
		return;
	}

	_EXIT = 1;

	fbr_test_ok(test);
	assert_zero(_ERROR);

	fbr_test_log(test->context, FBR_LOG_VERY_VERBOSE, "shutdown");

	struct fbr_test_finish *finish, *temp;

	TAILQ_FOREACH_SAFE(finish, &test->finish_list, entry, temp) {
		assert(finish->magic == FBR_TEST_FINISH_MAGIC);

		TAILQ_REMOVE(&test->finish_list, finish, entry);

		fbr_test_context_ok(test->context);

		fbr_test_log(test->context, FBR_LOG_VERY_VERBOSE, "finishing %s", finish->name);

		finish->func(test->context);

		fbr_ZERO(finish);
		free(finish);
	}

	assert(TAILQ_EMPTY(&test->finish_list));

	pt_assert(pthread_mutex_unlock(&_FINISH_LOCK));
}

struct fbr_test_context *
fbr_test_get_ctx(void)
{
	assert_zero(_EXIT);
	fbr_test_ok(_TEST);
	fbr_test_context_ok(_TEST->context);
	return _TEST->context;
}

int
fbr_test_is_thread(void)
{
	if (_EXIT) {
		return 0;
	}

	fbr_test_ok(_TEST);

	if (pthread_self() == _TEST->thread) {
		return 1;
	}

	return 0;
}

// Called from test_do_abort, attempt to gracefully exit
void
fbr_test_force_error(void)
{
	if (_EXIT) {
		return;
	}

	fbr_test_ok(_TEST);

	_TEST->error = 1;

	if (fbr_test_is_thread()) {
		_TEST->stopped = 1;
		pthread_exit(NULL);
	}
}

// Called from test_do_abort, cleanup before it exits
void
fbr_test_cleanup(void)
{
	fbr_test_run_all_finish(_TEST);
}

// Called from a signal, start abort process
void
fbr_test_context_abort(void)
{
	fbr_test_ABORT("Signal caught");
}

int
fbr_test_is_forked(void)
{
	if (_EXIT) {
		return 0;
	}

	fbr_test_ok(_TEST);

	return _TEST->forked;
}

void
fbr_finish_ERROR(int cond, const char *msg)
{
	if (!cond) {
		return;
	}

	printf("ERROR: %s\n", msg);

	_ERROR = 1;
}
