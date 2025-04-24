/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_store.h"

void
fbr_json_writer_init(struct fbr_json_writer *json) {
	assert_dev(json);

	fbr_ZERO(json);
}

void
fbr_json_writer_add(struct fbr_fs *fs, struct fbr_json_writer *json, char *buffer,
    size_t buffer_len, int scratch)
{
	assert_dev(fs);
	assert_dev(json);

	struct fbr_json_buffer *jbuf = NULL;

	for (size_t i = 0; i < fbr_array_len(json->buffers); i++) {
		if (!json->buffers[i].magic) {
			jbuf = &json->buffers[i];
			jbuf->magic = FBR_JSON_BUFFER_MAGIC;

			assert_zero_dev(jbuf->do_free);

			break;
		}
	}

	if (!jbuf) {
		jbuf = calloc(1, sizeof(*jbuf));
		assert(jbuf);

		jbuf->magic = FBR_JSON_BUFFER_MAGIC;
		jbuf->do_free = 1;
	}

	fbr_json_buffer_ok(jbuf);

	if (buffer) {
		assert_dev(buffer_len);
		assert_zero_dev(jbuf->buffer_free);

		jbuf->buffer = buffer;
		jbuf->buffer_len = buffer_len;
	} else {
		jbuf->buffer = malloc(FBR_JSON_DEFAULT_BUFLEN);
		assert(jbuf->buffer);

		jbuf->buffer_len = FBR_JSON_DEFAULT_BUFLEN;
		jbuf->buffer_free = 1;

		fbr_fs_stat_add(&fs->stats.json_buffers);
	}

	struct fbr_json_buffer *current = NULL;

	if (scratch) {
		if (!json->scratch) {
			json->scratch = jbuf;
			return;
		}
		current = json->scratch;
	} else {
		if (!json->final) {
			json->final = jbuf;
			return;
		}
		current = json->final;
	}

	while (current->next) {
		current = current->next;
	}
	current->next = jbuf;

	return;
}

static void
_json_buffer_free(struct fbr_json_buffer *jbuf)
{
	while (jbuf) {
		fbr_json_buffer_ok(jbuf);

		struct fbr_json_buffer *next = jbuf->next;

		if (jbuf->buffer_free) {
			free(jbuf->buffer);
		}

		int do_free = jbuf->do_free;

		fbr_ZERO(jbuf);

		if (do_free) {
			free(jbuf);
		}

		jbuf = next;
	}
}

void
fbr_json_writer_free(struct fbr_json_writer *json) {
	assert_dev(json);

	_json_buffer_free(json->scratch);
	_json_buffer_free(json->final);

	fbr_ZERO(json);
}

static void
_json_buffer_debug(struct fbr_fs *fs, struct fbr_json_buffer *jbuf, const char *name)
{
	assert_dev(fs);
	assert_dev(jbuf);

	while (jbuf) {
		fbr_json_buffer_ok(jbuf);

		fs->log("JSON_INDEX %s pos: %zu len: %zu buf_free: %d free: %d", name,
			jbuf->buffer_pos, jbuf->buffer_len, jbuf->buffer_free, jbuf->do_free);

		jbuf = jbuf->next;
	}
}

void
fbr_json_writer_debug(struct fbr_fs *fs, struct fbr_json_writer *json)
{
	assert_dev(fs);
	assert_dev(fs->logger);
	assert(json);

	_json_buffer_debug(fs, json->scratch, "scratch");
	_json_buffer_debug(fs, json->final, "final");

	fs->log("JSON_INDEX gzipped: %d", json->gzipped);
}
