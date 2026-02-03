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
	config->init = 1;

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
	assert(config->init);
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

	assert_zero(RB_INSERT(fbr_config_tree, &config->key_tree, key));
}

const char *
fbr_config_get(struct fbr_config *config, const char *name, const char *fallback)
{
	fbr_config_ok(config);
	assert_zero(config->init);

	struct fbr_config_key find;
	find.magic = FBR_CONFIG_KEY_MAGIC;
	find.name = name;

	struct fbr_config_key *key = RB_FIND(fbr_config_tree, &config->key_tree, &find);
	if (!key) {
		return fallback;
	}

	fbr_config_key_ok(key);

	return key->value;
}

long
fbr_config_get_long(struct fbr_config *config, const char *name, long fallback)
{
	fbr_config_ok(config);
	assert_zero(config->init);

	struct fbr_config_key find;
	find.magic = FBR_CONFIG_KEY_MAGIC;
	find.name = name;

	struct fbr_config_key *key = RB_FIND(fbr_config_tree, &config->key_tree, &find);
	if (!key) {
		return fallback;
	}

	fbr_config_key_ok(key);

	if (!key->is_long) {
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
