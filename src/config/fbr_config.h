/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_CONFIG_H_INCLUDED_
#define _FBR_CONFIG_H_INCLUDED_

#include <stddef.h>

#include "data/tree.h"

struct fbr_config_key {
	unsigned int			magic;
#define FBR_CONFIG_KEY_MAGIC		0xAA9D1921

	const char			*key;
	const char			*value;

	RB_ENTRY(fbr_config_key)	entry;

	char				_data[];
};

RB_HEAD(fbr_config_tree, fbr_config_key);

struct fbr_config {
	unsigned int			magic;
#define FBR_CONFIG_MAGIC		0xC9BBC9DC

	struct fbr_config_tree		key_tree;
};

struct fbr_config *fbr_config_alloc(void);
void fbr_config_add(struct fbr_config *config, const char *key, size_t key_len,
	const char *value, size_t value_len);
void fbr_config_free(struct fbr_config *config);

#define fbr_config_ok(config)		fbr_magic_check(config, FBR_CONFIG_MAGIC)
#define fbr_config_key_ok(key)		fbr_magic_check(key, FBR_CONFIG_KEY_MAGIC)

#endif /* _FBR_CONFIG_H_INCLUDED_ */
