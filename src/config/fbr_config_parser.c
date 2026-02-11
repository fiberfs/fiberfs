/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_config.h"

size_t
fbr_config_parse(struct fbr_config *config, const char *filepath)
{
	fbr_config_ok(config);
	assert(filepath);
	static_ASSERT(FBR_CONFIG_MAX_FILE_LINE > 0);

	FILE *f = fopen(filepath, "r");
	if (!f) {
		fbr_atomic_add(&config->stats.errors, 1);
		return 0;
	}

	char line_buffer[FBR_CONFIG_MAX_FILE_LINE + 2];
	const size_t line_end = sizeof(line_buffer) - 2;
	int line_error = 0;
	size_t entries = 0;

	while (1) {
		line_buffer[line_end] = '\n';

		char *line = fgets(line_buffer, sizeof(line_buffer), f);
		if (!line) {
			break;
		}

		if (line_buffer[line_end] && line_buffer[line_end] != '\n') {
			// Overflow, drain the line and continue
			line_error = 1;
			continue;
		} else if (line_error) {
			fbr_atomic_add(&config->stats.errors, 1);
			line_error = 0;
			continue;
		}

		char *name = line_buffer;
		size_t name_len = 0;

		while (name[name_len] && name[name_len] != '=' && name[name_len] != '\n') {
			name_len++;
			assert(name_len <= line_end);
		}

		FBR_TRIM_STR_LEFT(name, name_len);

		if (name_len == 0) {
			if (name[0] == '=') {
				fbr_atomic_add(&config->stats.errors, 1);
			}
			continue;
		} else if (name[0] == '#') {
			continue;
		} else if (name[name_len] != '=') {
			fbr_atomic_add(&config->stats.errors, 1);
			continue;
		}

		name[name_len] = '\0';

		char *value = name + name_len + 1;
		size_t value_len = strlen(value);

		FBR_TRIM_STR(name, name_len);
		FBR_TRIM_STR(value, value_len);

		fbr_config_add(config, name, name_len, value, value_len);

		entries++;
	}

	if (!feof(f)) {
		fbr_atomic_add(&config->stats.errors, 1);
	}

	int ret = fclose(f);
	if (ret) {
		fbr_atomic_add(&config->stats.errors, 1);
	}

	return entries;
}
