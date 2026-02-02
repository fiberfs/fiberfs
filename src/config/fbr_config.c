/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdlib.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_config.h"

static int _config_key_cmp(const struct fbr_config_key *key1, const struct fbr_config_key *key2);

RB_GENERATE_STATIC(fbr_config_tree, fbr_config_key, entry, _config_key_cmp)

struct fbr_config *
fbr_config_alloc(void)
{
	struct fbr_config *config = malloc(sizeof(*config));
	assert(config);

	config->magic = FBR_CONFIG_MAGIC;

	RB_INIT(&config->key_tree);

	fbr_config_ok(config);

	return config;
}

static int
_config_key_cmp(const struct fbr_config_key *k1, const struct fbr_config_key *k2)
{
	fbr_config_key_ok(k1);
	fbr_config_key_ok(k2);

	return strcmp(k1->key, k2->key);
}

void
fbr_config_add(struct fbr_config *config, const char *key_name, size_t key_name_len,
    const char *value, size_t value_len)
{
	fbr_config_ok(config);
	assert(key_name && key_name_len);

	key_name_len++;
	value_len++;

	struct fbr_config_key *key = malloc(sizeof(*key) + key_name_len + value_len);
	assert(key);

	key->magic = FBR_CONFIG_KEY_MAGIC;
	key->key = key->_data;

	fbr_strcpy(key->_data, key_name_len, key_name);

	if (value) {
		key->value = key->_data + key_name_len;

		fbr_strcpy(key->_data + key_name_len, value_len, value);
	} else {
		assert_dev(value_len == 1);
		key->value = NULL;
	}

	assert_zero(RB_INSERT(fbr_config_tree, &config->key_tree, key));
}

const char *
fbr_config_get(struct fbr_config *config, const char *key_name)
{
	fbr_config_ok(config);

	struct fbr_config_key find;
	find.magic = FBR_CONFIG_KEY_MAGIC;
	find.key = key_name;

	struct fbr_config_key *key = RB_FIND(fbr_config_tree, &config->key_tree, &find);

	if (!key) {
		return NULL;
	}

	fbr_config_key_ok(key);

	return key->value;
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

	struct fbr_config_key *key, *next;
	RB_FOREACH_SAFE(key, fbr_config_tree, &config->key_tree, next) {
		fbr_config_key_ok(key);

		(void)RB_REMOVE(fbr_config_tree, &config->key_tree, key);

		_config_key_free(key);
	}

	assert(RB_EMPTY(&config->key_tree));

	fbr_zero(config);

	free(config);
}
