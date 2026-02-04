/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_CONFIG_H_INCLUDED_
#define _FBR_CONFIG_H_INCLUDED_

#include <pthread.h>
#include <stddef.h>

#include "data/tree.h"

struct fbr_config_key {
	unsigned int			magic;
#define FBR_CONFIG_KEY_MAGIC		0xAA9D1921

	unsigned int			is_long:1;
	unsigned int			deleted:1;

	const char			*name;
	const char			*value;
	long				long_value;

	RB_ENTRY(fbr_config_key)	entry;
	struct fbr_config_key		*next;

	char				_data[];
};

RB_HEAD(fbr_config_tree, fbr_config_key);

struct fbr_config {
	unsigned int			magic;
#define FBR_CONFIG_MAGIC		0xC9BBC9DC

	unsigned int			do_free:1;

	pthread_rwlock_t		rwlock;

	struct fbr_config_tree		key_tree;
	struct fbr_config_key		*deleted;

	fbr_stats_t			stat_keys;
	fbr_stats_t			stat_deleted;
};

extern struct fbr_config *_CONFIG;

struct fbr_config *fbr_config_alloc(void);
void fbr_config_add(struct fbr_config *config, const char *name, size_t name_len,
	const char *value, size_t value_len);
const char *fbr_config_get(struct fbr_config *config, const char *name, const char *fallback);
long fbr_config_get_long(struct fbr_config *config, const char *name, long fallback);
void fbr_config_free(struct fbr_config *config);

#define fbr_config_ok(config)		fbr_magic_check(config, FBR_CONFIG_MAGIC)
#define fbr_config_key_ok(key)		fbr_magic_check(key, FBR_CONFIG_KEY_MAGIC)

#endif /* _FBR_CONFIG_H_INCLUDED_ */
