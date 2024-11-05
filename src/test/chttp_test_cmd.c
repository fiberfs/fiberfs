/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/chttp_test.h"

#include <stdio.h>
#include <stdlib.h>

static int chttp_test_entry_cmp(const struct fbr_test_cmdentry *k1,
    const struct fbr_test_cmdentry *k2);

RB_GENERATE_STATIC(fbr_test_tree, fbr_test_cmdentry, entry, chttp_test_entry_cmp)

static int
chttp_test_entry_cmp(const struct fbr_test_cmdentry *k1,
    const struct fbr_test_cmdentry *k2)
{
	assert(k1);
	assert(k2);

	return strcmp(k1->name, k2->name);
}

static void
_test_cmd_register(struct fbr_test *test, const char *name, chttp_test_cmd_f *func)
{
	struct fbr_test_cmdentry *entry, *ret;

	chttp_test_ok(test);

	entry = malloc(sizeof(*entry));
	assert(entry);

	chttp_ZERO(entry);

	entry->magic = FBR_TEST_ENTRY_MAGIC;
	entry->name = name;
	entry->cmd_func = func;
	entry->is_cmd = 1;

	ret = RB_INSERT(fbr_test_tree, &test->cmd_tree, entry);
	assert_zero(ret);
}

static void
_test_var_register(struct fbr_test *test, const char *name, chttp_test_var_f *func)
{
	struct fbr_test_cmdentry *entry, *ret;

	chttp_test_ok(test);

	entry = malloc(sizeof(*entry));
	assert(entry);

	chttp_ZERO(entry);

	entry->magic = FBR_TEST_ENTRY_MAGIC;
	entry->name = name;
	entry->var_func = func;
	entry->is_var = 1;

	ret = RB_INSERT(fbr_test_tree, &test->cmd_tree, entry);
	assert_zero(ret);
}

static void
_test_cmds_free(struct chttp_test_context *ctx)
{
	struct fbr_test *test;
	struct fbr_test_cmdentry *entry, *next;

	test = chttp_test_convert(ctx);
	chttp_test_ok(test);

	RB_FOREACH_SAFE(entry, fbr_test_tree, &test->cmd_tree, next) {
		assert(entry->magic == FBR_TEST_ENTRY_MAGIC);

		RB_REMOVE(fbr_test_tree, &test->cmd_tree, entry);

		chttp_ZERO(entry);
		free(entry);
	}

	assert(RB_EMPTY(&test->cmd_tree));
}

void
chttp_test_cmds_init(struct fbr_test *test)
{
	chttp_test_ok(test);
	assert(RB_EMPTY(&test->cmd_tree));

#define CHTTP_TEST_CMD(cmd)					\
	_test_cmd_register(test, #cmd, &chttp_test_cmd_##cmd);
#define CHTTP_TEST_VAR(var)					\
	_test_var_register(test, "$" #var, &chttp_test_var_##var);
#include "test/chttp_test_cmds.h"

	chttp_test_register_finish(&test->context, "cmd", _test_cmds_free);
}

struct fbr_test_cmdentry *
chttp_test_cmds_get(struct fbr_test *test, const char *name)
{
	struct fbr_test_cmdentry *result, find;

	chttp_test_ok(test);
	assert(name);

	find.name = name;

	result = RB_FIND(fbr_test_tree, &test->cmd_tree, &find);

	if (!result) {
		return NULL;
	}

	assert(result->magic == FBR_TEST_ENTRY_MAGIC);

	return result;
}
