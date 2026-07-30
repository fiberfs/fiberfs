/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <stdlib.h>

#include "data/tree.h"
#include "test/fbr_test.h"
#include "test/commands/fbr_test_cmds.h"

struct _test_var_entry {
	unsigned int			magic;
#define _VAR_ENTRY_MAGIC		0x214BC26C

	RB_ENTRY(_test_var_entry)	entry;

	const char			*name;
	char				*value;
};

RB_HEAD(_test_var_tree, _test_var_entry);

struct fbr_test_var {
	unsigned int			magic;
#define _VAR_MAGIC			0x951348BB

	struct _test_var_tree		var_tree;
	pthread_mutex_t			var_lock;
};

static int _test_var_entry_cmp(const struct _test_var_entry *e1,
    const struct _test_var_entry *e2);

RB_GENERATE_STATIC(_test_var_tree, _test_var_entry, entry, _test_var_entry_cmp)

static int
_test_var_entry_cmp(const struct _test_var_entry *e1, const struct _test_var_entry *e2)
{
	fbr_magic_check(e1, _VAR_ENTRY_MAGIC);
	fbr_magic_check(e2, _VAR_ENTRY_MAGIC);

	return strcmp(e1->name, e2->name);
}

static void
_var_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	fbr_magic_check(ctx->var, _VAR_MAGIC);

	pt_assert(pthread_mutex_destroy(&ctx->var->var_lock));

	struct _test_var_entry *entry, *next;

	RB_FOREACH_SAFE(entry, _test_var_tree, &ctx->var->var_tree, next) {
		fbr_magic_check(entry, _VAR_ENTRY_MAGIC);

		RB_REMOVE(_test_var_tree, &ctx->var->var_tree, entry);

		free((char*)entry->name);
		free(entry->value);

		fbr_zero(entry);
		free(entry);
	}

	assert(RB_EMPTY(&ctx->var->var_tree));

	fbr_zero(ctx->var);
	free(ctx->var);

	ctx->var = NULL;
}

static void
_var_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	if (!ctx->var) {
		struct fbr_test_var *var = calloc(1, sizeof(*var));
		assert(var);

		var->magic = _VAR_MAGIC;

		RB_INIT(&var->var_tree);
		pt_assert(pthread_mutex_init(&var->var_lock, NULL));

		ctx->var = var;

		fbr_test_register_finish(ctx, "var", _var_finish);
	}

	fbr_magic_check(ctx->var, _VAR_MAGIC);
}

void
fbr_cmd_set(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_var_init(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ASSERT(cmd->param_count > 0, "Pass in a variable name");
	assert(cmd->params[0].len);

	struct fbr_test_var *var = ctx->var;

	size_t name_len = cmd->params[0].len + 2;
	char *name = malloc(name_len);
	assert(name);
	fbr_snprintf(name, name_len, "$%s", cmd->params[0].value);

	size_t len = 0;

	for (size_t i = 1; i < cmd->param_count; i++) {
		fbr_test_unescape(&cmd->params[i]);
		len += cmd->params[i].len;
	}

	struct _test_var_entry find;
	find.magic = _VAR_ENTRY_MAGIC;
	find.name = name;

	pt_assert(pthread_mutex_lock(&var->var_lock));

	struct _test_var_entry *var_entry = RB_FIND(_test_var_tree, &var->var_tree, &find);
	if (var_entry) {
		fbr_magic_check(var_entry, _VAR_ENTRY_MAGIC);

		free(name);
		free(var_entry->value);

		var_entry->value = NULL;
	} else {
		var_entry = calloc(1, sizeof(*var_entry));
		assert(var_entry);

		var_entry->magic = _VAR_ENTRY_MAGIC;
		var_entry->name = name;

		struct _test_var_entry *ret = RB_INSERT(_test_var_tree, &var->var_tree,
			var_entry);
		assert_zero(ret);

		fbr_test_var_register(ctx->test, var_entry->name, fbr_var_get);
	}

	assert_zero_dev(var_entry->value);

	var_entry->value = malloc(len + 1);
	assert(var_entry->value);

	len = 0;

	for (size_t i = 1; i < cmd->param_count; i++) {
		memcpy(&var_entry->value[len], cmd->params[i].value, cmd->params[i].len);
		len += cmd->params[i].len;
	}

	var_entry->value[len] = '\0';

	pt_assert(pthread_mutex_unlock(&var->var_lock));
}

const char *
fbr_var_get(struct fbr_test_context *ctx)
{
	_var_init(ctx);
	fbr_test_ok(ctx->test);

	struct fbr_test_var *var = ctx->var;
	const char *name = ctx->test->variable;
	assert(name);

	struct _test_var_entry find;
	find.magic = _VAR_ENTRY_MAGIC;
	find.name = name;

	pt_assert(pthread_mutex_lock(&var->var_lock));

	struct _test_var_entry *var_entry = RB_FIND(_test_var_tree, &var->var_tree, &find);
	fbr_magic_check(var_entry, _VAR_ENTRY_MAGIC);
	assert(var_entry->value);

	pt_assert(pthread_mutex_unlock(&var->var_lock));

	return var_entry->value;
}
