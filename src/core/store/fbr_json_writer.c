/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_store.h"
#include "core/request/fbr_request.h"

static void
_json_buffer_add(struct fbr_fs *fs, struct fbr_json_writer *json, char *buffer,
    size_t buffer_len, int scratch)
{
	assert_dev(fs);
	assert(json);

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

	struct fbr_json_buffer **head = NULL;
	struct fbr_json_buffer *current = NULL;

	if (scratch) {
		head = &json->scratch;
		current = json->scratch;
	} else {
		head = &json->final;
		current = json->final;
	}
	while (current && current->next) {
		current = current->next;
	}

	if (buffer) {
		assert_dev(buffer_len);
		assert_zero_dev(jbuf->buffer_free);

		jbuf->buffer = buffer;
		jbuf->buffer_len = buffer_len;
	} else {
		assert_zero_dev(buffer_len);
		buffer_len = FBR_JSON_DEFAULT_BUFLEN;
		if (current) {
			buffer_len = current->buffer_len * 2;
		}

		jbuf->buffer = malloc(buffer_len);
		assert(jbuf->buffer);

		jbuf->buffer_len = buffer_len;
		jbuf->buffer_free = 1;

		fbr_fs_stat_add(&fs->stats.json_buffers);
	}

	if (!current) {
		*head = jbuf;
		return;
	} else {
		current->next = jbuf;
	}
}

void
fbr_json_writer_init(struct fbr_fs *fs, struct fbr_json_writer *json, int want_gzip)
{
	fbr_fs_ok(fs);
	assert(json);

	fbr_ZERO(json);

	struct fbr_request *request = fbr_request_get();

	if (request) {
		fbr_request_ok(request);

		char *buffer = fbr_workspace_alloc(request->workspace, FBR_JSON_DEFAULT_BUFLEN);
		size_t buffer_len = FBR_JSON_DEFAULT_BUFLEN;

		if (buffer) {
			_json_buffer_add(fs, json, buffer, buffer_len, 1);
			assert_dev(json->scratch);
		}

		buffer = fbr_workspace_rbuffer(request->workspace);
		buffer_len = fbr_workspace_rlen(request->workspace);

		if (buffer && buffer_len >= FBR_JSON_DEFAULT_BUFLEN) {
			if (buffer_len >= FBR_JSON_DEFAULT_BUFLEN * 2) {
				buffer_len -= FBR_JSON_DEFAULT_BUFLEN;
			} else if (buffer_len > FBR_JSON_DEFAULT_BUFLEN) {
				buffer_len = FBR_JSON_DEFAULT_BUFLEN;
			}

			fbr_workspace_ralloc(request->workspace, buffer_len);

			_json_buffer_add(fs, json, buffer, buffer_len, 0);
			assert_dev(json->final);
		} else if (buffer) {
			fbr_workspace_ralloc(request->workspace, 0);
		}
	}

	if (!json->scratch) {
		_json_buffer_add(fs, json, NULL, 0, 1);
	}
	if (!json->final) {
		_json_buffer_add(fs, json, NULL, 0, 0);
	}

	json->want_gzip = want_gzip;
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
fbr_json_writer_free(struct fbr_fs *fs, struct fbr_json_writer *json)
{
	fbr_fs_ok(fs);
	assert(json);

	_json_buffer_free(json->scratch);
	_json_buffer_free(json->final);

	fbr_ZERO(json);
}

static void
_json_scratch_reset(struct fbr_json_writer *json)
{
	assert_dev(json);
	assert_dev(json->scratch);

	_json_buffer_free(json->scratch->next);

	json->scratch->buffer_pos = 0;
	json->scratch->next = NULL;
}

static void
_json_buffer_append(struct fbr_json_buffer *jbuf, const char *buffer, size_t buffer_len)
{
	assert_dev(jbuf);
	assert_dev(buffer);
	assert_dev(buffer_len);

	memcpy(jbuf->buffer + jbuf->buffer_pos, buffer, buffer_len);
	jbuf->buffer_pos += buffer_len;

	assert(jbuf->buffer_len >= jbuf->buffer_pos);
}

static void
_json_copy_final(struct fbr_fs *fs, struct fbr_json_writer *json)
{
	assert_dev(fs);
	assert_dev(json);
	assert_dev(json->scratch);
	assert_dev(json->final);

	struct fbr_json_buffer *scratch = json->scratch;
	struct fbr_json_buffer *final = json->final;

	while (final->next) {
		final = final->next;
	}

	size_t scratch_offset = 0;
	size_t scratch_size;

	while (scratch && scratch->buffer_pos) {
		fbr_json_buffer_ok(scratch);
		fbr_json_buffer_ok(final);
		assert_dev(final->buffer_len >= final->buffer_pos);

		size_t final_free = final->buffer_len - final->buffer_pos;

		if (final_free) {
			scratch_size = scratch->buffer_pos - scratch_offset;
			if (scratch_size > final_free) {
				scratch_size = final_free;
			}

			_json_buffer_append(final, scratch->buffer + scratch_offset,
				scratch_size);

			scratch_offset += scratch_size;
			assert_dev(scratch_offset <= scratch->buffer_pos);
		}

		if (scratch_offset == scratch->buffer_pos) {
			scratch = scratch->next;
			scratch_offset = 0;
			continue;
		}

		assert_dev(final->buffer_pos == final->buffer_len);
		assert_zero_dev(final->next);

		_json_buffer_add(fs, json, NULL, 0, 0);

		final = final->next;
		assert_dev(final);
	}

	_json_scratch_reset(json);
}

void
fbr_json_writer_add(struct fbr_fs *fs, struct fbr_json_writer *json, char *buffer,
    size_t buffer_len)
{
	fbr_fs_ok(fs);
	assert(json);

	if (!buffer) {
		assert_zero_dev(buffer_len);
		_json_copy_final(fs, json);
		return;
	}

	assert(buffer);
	assert(buffer_len);

	struct fbr_json_buffer *scratch = json->scratch;
	fbr_json_buffer_ok(scratch);
	assert_dev(scratch->buffer_len);
	assert_dev(scratch->buffer_len >= scratch->buffer_pos);
	assert_zero_dev(scratch->next);

	size_t scratch_free = scratch->buffer_len - scratch->buffer_pos;
	int do_flush = 0;

	if (buffer_len <= scratch_free) {
		_json_buffer_append(scratch, buffer, buffer_len);
	} else {
		_json_buffer_add(fs, json, buffer, buffer_len, 1);
		assert_dev(scratch->next);

		scratch->next->buffer_pos = buffer_len;
		do_flush = 1;
	}

	if (do_flush) {
		// TODO compress
		_json_copy_final(fs, json);
	}
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
	fbr_fs_ok(fs);
	assert_dev(fs->logger);
	assert(json);

	_json_buffer_debug(fs, json->scratch, "scratch");
	_json_buffer_debug(fs, json->final, "final");

	fs->log("JSON_INDEX want_gzip: %d", json->want_gzip);
	fs->log("JSON_INDEX is_gzip: %d", json->is_gzip);
}
