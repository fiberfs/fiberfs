/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_config.h"

struct fbr_config __CONFIG = {
	FBR_CONFIG_MAGIC,
	0,
	PTHREAD_RWLOCK_INITIALIZER,
	RB_INITIALIZER(__CONFIG.key_tree),
	NULL,
	0, 0
}, *_CONFIG = &__CONFIG;

static int _config_key_cmp(const struct fbr_config_key *key1, const struct fbr_config_key *key2);

RB_GENERATE_STATIC(fbr_config_tree, fbr_config_key, entry, _config_key_cmp)

struct fbr_config *
fbr_config_alloc(void)
{
	struct fbr_config *config = calloc(1, sizeof(*config));
	assert(config);

	config->magic = FBR_CONFIG_MAGIC;
	config->do_free = 1;

	pt_assert(pthread_rwlock_init(&config->rwlock, NULL));
	RB_INIT(&config->key_tree);

	fbr_config_ok(config);

	return config;
}

static int
_config_key_cmp(const struct fbr_config_key *key1, const struct fbr_config_key *key2)
{
	fbr_config_key_ok(key1);
	fbr_config_key_ok(key2);

	return strcmp(key1->name, key2->name);
}

static void
_config_parse_long(struct fbr_config_key *key, size_t value_len)
{
	assert_dev(key);
	assert_zero_dev(key->is_long);

	if (value_len == 0) {
		return;
	}

	const char *s = key->value;
	if (*s == '-') {
		s++;
	}

	while (s < key->value + value_len) {
		if (*s < '0' || *s > '9') {
			return;
		}

		s++;
	}

	int error;

	key->long_value = fbr_parse_long(key->value, value_len, &error);

	if (!error) {
		key->is_long = 1;
	}
}

void
fbr_config_add(struct fbr_config *config, const char *name, size_t name_len,
    const char *value, size_t value_len)
{
	fbr_config_ok(config);
	assert(name && name_len);

	name_len++;
	value_len++;

	struct fbr_config_key *key = calloc(1, sizeof(*key) + name_len + value_len);
	assert(key);

	key->magic = FBR_CONFIG_KEY_MAGIC;
	key->name = key->_data;

	fbr_strcpy(key->_data, name_len, name);

	if (value) {
		key->value = key->_data + name_len;

		fbr_strcpy(key->_data + name_len, value_len, value);
	} else {
		assert_dev(value_len == 1);
		key->value = NULL;
	}

	_config_parse_long(key, value_len - 1);

	pt_assert(pthread_rwlock_wrlock(&config->rwlock));
	fbr_config_ok(config);

	struct fbr_config_key *existing = RB_INSERT(fbr_config_tree, &config->key_tree, key);

	if (existing) {
		fbr_config_key_ok(existing);
		assert_zero(existing->deleted);
		assert_zero(existing->next);

		(void)RB_REMOVE(fbr_config_tree, &config->key_tree, existing);
		assert_zero(RB_INSERT(fbr_config_tree, &config->key_tree, key));

		existing->next = config->deleted;
		config->deleted = existing;

		existing->deleted = 1;
		config->stat_deleted++;
	} else {
		config->stat_keys++;
	}

	pt_assert(pthread_rwlock_unlock(&config->rwlock));
}

static struct fbr_config_key *
_config_get(struct fbr_config *config, const char *name)
{
	assert_dev(config);
	assert_dev(name);

	struct fbr_config_key find;
	find.magic = FBR_CONFIG_KEY_MAGIC;
	find.name = name;

	pt_assert(pthread_rwlock_rdlock(&config->rwlock));
	fbr_config_ok(config);

	struct fbr_config_key *key = RB_FIND(fbr_config_tree, &config->key_tree, &find);

	pt_assert(pthread_rwlock_unlock(&config->rwlock));

	if (!key) {
		return NULL;
	}

	fbr_config_key_ok(key);

	return key;
}

const char *
fbr_config_get(struct fbr_config *config, const char *name, const char *fallback)
{
	fbr_config_ok(config);
	assert(name);

	struct fbr_config_key *key = _config_get(config, name);

	if (!key) {
		return fallback;
	}

	return key->value;
}

long
fbr_config_get_long(struct fbr_config *config, const char *name, long fallback)
{
	fbr_config_ok(config);
	assert(name);

	struct fbr_config_key *key = _config_get(config, name);

	if (!key || !key->is_long) {
		return fallback;
	}

	return key->long_value;
}

static void
_config_key_free(struct fbr_config_key *key)
{
	assert_dev(key);

	fbr_zero(key);
	free(key);
}

void
fbr_config_free(struct fbr_config *config)
{
	fbr_config_ok(config);

	pt_assert(pthread_rwlock_wrlock(&config->rwlock));
	fbr_config_ok(config);

	int do_free = config->do_free;

	struct fbr_config_key *key, *next;
	RB_FOREACH_SAFE(key, fbr_config_tree, &config->key_tree, next) {
		fbr_config_key_ok(key);
		assert_zero(key->deleted);

		(void)RB_REMOVE(fbr_config_tree, &config->key_tree, key);

		_config_key_free(key);

		config->stat_keys--;
	}

	assert(RB_EMPTY(&config->key_tree));
	assert_zero(config->stat_keys);

	while (config->deleted) {
		key = config->deleted;
		config->deleted = key->next;

		fbr_config_key_ok(key);
		assert(key->deleted);

		_config_key_free(key);

		config->stat_deleted--;
	}

	assert_zero(config->stat_deleted);

	config->magic = 0;

	pt_assert(pthread_rwlock_unlock(&config->rwlock));

	pt_assert(pthread_rwlock_destroy(&config->rwlock));
	fbr_zero(config);

	if (do_free) {
		free(config);
	}

	if (config == _CONFIG) {
		_CONFIG = NULL;
	}
}
