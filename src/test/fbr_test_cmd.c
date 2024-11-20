/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "test/fbr_test.h"
#include "test/fbr_test_cmds.h"
#include "test/chttp_test_cmds.h"
#include "test/fjson_test_cmds.h"

#include <stdio.h>
#include <stdlib.h>

static int fbr_test_entry_cmp(const struct fbr_test_cmdentry *k1,
    const struct fbr_test_cmdentry *k2);

RB_GENERATE_STATIC(fbr_test_tree, fbr_test_cmdentry, entry, fbr_test_entry_cmp)

static int
fbr_test_entry_cmp(const struct fbr_test_cmdentry *k1,
    const struct fbr_test_cmdentry *k2)
{
	assert(k1);
	assert(k2);

	return strcmp(k1->name, k2->name);
}

static struct fbr_test_cmdentry *
_test_cmd_alloc(struct fbr_test *test)
{
	struct fbr_test_cmdentry *entry;
	size_t size;

	fbr_test_ok(test);
	assert(test->cmds_pos <= test->cmds_size);

	if (test->cmds_pos == test->cmds_size) {
		if (test->cmds_size == 0) {
			test->cmds_size = 128;
		} else {
			size = test->cmds_size * 2;
			assert(size / 2 == test->cmds_size);
			test->cmds_size = size;
		}

		size = test->cmds_size * sizeof(*test->cmds);
		assert(size / sizeof(*test->cmds) == test->cmds_size);

		test->cmds = realloc(test->cmds, size);
		assert(test->cmds);
	}
	assert(test->cmds_pos < test->cmds_size);

	entry = &test->cmds[test->cmds_pos];
	fbr_ZERO(entry);
	entry->magic = FBR_TEST_ENTRY_MAGIC;

	test->cmds_pos++;

	return entry;
}

static void
_test_cmd_register(struct fbr_test *test, const char *name, fbr_test_cmd_f *func)
{
	struct fbr_test_cmdentry *entry, *ret;

	fbr_test_ok(test);

	entry = _test_cmd_alloc(test);
	assert(entry);

	entry->name = name;
	entry->cmd_func = func;
	entry->is_cmd = 1;

	ret = RB_INSERT(fbr_test_tree, &test->cmd_tree, entry);
	assert_zero(ret);
}

static void
_test_var_register(struct fbr_test *test, const char *name, fbr_test_var_f *func)
{
	struct fbr_test_cmdentry *entry, *ret;

	fbr_test_ok(test);

	entry = _test_cmd_alloc(test);
	assert(entry);

	entry->name = name;
	entry->var_func = func;
	entry->is_var = 1;

	ret = RB_INSERT(fbr_test_tree, &test->cmd_tree, entry);
	assert_zero(ret);
}

static void
_test_cmds_free(struct fbr_test_context *ctx)
{
	struct fbr_test *test;
	struct fbr_test_cmdentry *entry, *next;

	test = fbr_test_convert(ctx);
	fbr_test_ok(test);

	RB_FOREACH_SAFE(entry, fbr_test_tree, &test->cmd_tree, next) {
		assert(entry->magic == FBR_TEST_ENTRY_MAGIC);

		RB_REMOVE(fbr_test_tree, &test->cmd_tree, entry);

		fbr_ZERO(entry);
	}

	assert(RB_EMPTY(&test->cmd_tree));

	free(test->cmds);

	test->cmds = NULL;
	test->cmds_size = 0;
}

void
fbr_test_cmds_init(struct fbr_test *test)
{
	fbr_test_ok(test);
	assert(RB_EMPTY(&test->cmd_tree));

#undef FBR_TEST_CMDS_H_INCLUDED
#define FBR_TEST_CMD(cmd)					\
	_test_cmd_register(test, #cmd, &fbr_test_cmd_##cmd);
#define FBR_TEST_VAR(var)					\
	_test_var_register(test, "$" #var, &fbr_test_var_##var);
#include "test/fbr_test_cmds.h"

#undef CHTTP_TEST_CMDS_H_INCLUDED
#define CHTTP_TEST_CMD(cmd)					\
	_test_cmd_register(test, #cmd, &chttp_test_cmd_##cmd);
#define CHTTP_TEST_VAR(var)					\
	_test_var_register(test, "$" #var, &chttp_test_var_##var);
#include "test/chttp_test_cmds.h"

#undef FJSON_TEST_CMDS_H_INCLUDED
#define FJSON_TEST_CMD(cmd)					\
	_test_cmd_register(test, #cmd, &fjson_cmd_##cmd);
#define FJSON_TEST_VAR(var)					\
	_test_var_register(test, "$" #var, &fjson_var_##var);
#include "test/fjson_test_cmds.h"

	fbr_test_register_finish(test->context, "cmd", _test_cmds_free);
}

struct fbr_test_cmdentry *
fbr_test_cmds_get(struct fbr_test *test, const char *name)
{
	struct fbr_test_cmdentry *result, find;

	fbr_test_ok(test);
	assert(name);

	find.name = name;

	result = RB_FIND(fbr_test_tree, &test->cmd_tree, &find);

	if (!result) {
		return NULL;
	}

	assert(result->magic == FBR_TEST_ENTRY_MAGIC);

	return result;
}
