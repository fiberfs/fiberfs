/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "test/fbr_test.h"
#include "test/fbr_test_cmds.h"
#include "test/chttp_test_cmds.h"
#include "test/fjson_test_cmds.h"
#include "fuse/test/fbr_test_fuse_cmds.h"

#include <stdio.h>
#include <stdlib.h>

static int _test_entry_cmp(const struct fbr_test_cmdentry *k1,
    const struct fbr_test_cmdentry *k2);

RB_GENERATE_STATIC(fbr_test_tree, fbr_test_cmdentry, entry, _test_entry_cmp)

static int
_test_entry_cmp(const struct fbr_test_cmdentry *k1, const struct fbr_test_cmdentry *k2)
{
	assert(k1);
	assert(k2);

	return strcmp(k1->name, k2->name);
}

static struct fbr_test_cmdentry *
_test_cmd_alloc(struct fbr_test *test)
{
	fbr_test_ok(test);

	if (test->cmds_size == 0) {
		test->cmds_size = 256;
		size_t size = test->cmds_size * sizeof(*test->cmds);
		test->cmds = malloc(size);
		assert(test->cmds);
	}

	assert(test->cmds_pos < test->cmds_size);

	struct fbr_test_cmdentry *entry = &test->cmds[test->cmds_pos];
	fbr_ZERO(entry);
	entry->magic = FBR_TEST_ENTRY_MAGIC;

	test->cmds_pos++;

	return entry;
}

static void
_test_cmd_register(struct fbr_test *test, const char *name, fbr_test_cmd_f *func)
{
	fbr_test_ok(test);

	struct fbr_test_cmdentry *entry = _test_cmd_alloc(test);
	assert(entry);

	entry->name = name;
	entry->cmd_func = func;
	entry->is_cmd = 1;

	struct fbr_test_cmdentry *ret = RB_INSERT(fbr_test_tree, &test->cmd_tree, entry);
	assert_zero(ret);
}

static void
_test_var_register(struct fbr_test *test, const char *name, fbr_test_var_f *func)
{
	fbr_test_ok(test);

	struct fbr_test_cmdentry *entry = _test_cmd_alloc(test);
	assert(entry);

	entry->name = name;
	entry->var_func = func;
	entry->is_var = 1;

	struct fbr_test_cmdentry *ret = RB_INSERT(fbr_test_tree, &test->cmd_tree, entry);
	assert_zero(ret);
}

static void
_test_cmds_free(struct fbr_test_context *ctx)
{
	struct fbr_test *test = fbr_test_convert(ctx);
	fbr_test_ok(test);

	struct fbr_test_cmdentry *entry, *next;

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

#undef FBR_TEST_FUSE_CMDS_H_INCLUDED
#define FBR_TEST_FUSE_CMD(cmd)					\
	_test_cmd_register(test, #cmd, &fbr_test_fuse_cmd_##cmd);
#define FBR_TEST_FUSE_VAR(var)					\
	_test_var_register(test, "$" #var, &fbr_test_fuse_var_##var);
#include "fuse/test/fbr_test_fuse_cmds.h"

	fbr_test_register_finish(test->context, "cmd", _test_cmds_free);
}

struct fbr_test_cmdentry *
fbr_test_cmds_get(struct fbr_test *test, const char *name)
{
	fbr_test_ok(test);
	assert(name);

	struct fbr_test_cmdentry find;
	find.name = name;

	struct fbr_test_cmdentry *result = RB_FIND(fbr_test_tree, &test->cmd_tree, &find);

	if (!result) {
		return NULL;
	}

	assert(result->magic == FBR_TEST_ENTRY_MAGIC);

	return result;
}
