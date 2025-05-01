/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_store.h"
#include "core/request/fbr_request.h"

static void
_buffer_add(struct fbr_fs *fs, struct fbr_writer *writer, char *buffer,
    size_t buffer_len, int scratch)
{
	assert_dev(fs);
	assert(writer);

	struct fbr_buffer **head = NULL;
	struct fbr_buffer *current = NULL;

	if (scratch) {
		head = &writer->scratch;
		current = writer->scratch;
	} else {
		head = &writer->final;
		current = writer->final;
	}
	while (current && current->next) {
		current = current->next;
	}

	if (!buffer) {
		assert_zero_dev(buffer_len);
		buffer_len = FBR_DEFAULT_BUFLEN;
		if (current) {
			buffer_len = current->buffer_len * 2;
		}
	}

	struct fbr_buffer *fbuf = NULL;

	for (size_t i = 0; i < fbr_array_len(writer->buffers); i++) {
		if (!writer->buffers[i].magic) {
			fbuf = &writer->buffers[i];
			fbuf->magic = FBR_BUFFER_MAGIC;

			assert_zero_dev(fbuf->do_free);

			break;
		}
	}

	if (!fbuf) {
		size_t buffer_alloc = 0;
		if (!buffer) {
			assert_dev(buffer_len);
			buffer_alloc = buffer_len;
		}

		fbuf = malloc(sizeof(*fbuf) + buffer_alloc);
		assert(fbuf);

		fbr_ZERO(fbuf);
		fbuf->magic = FBR_BUFFER_MAGIC;
		fbuf->do_free = 1;

		if (!buffer) {
			buffer = (char*)(fbuf + 1);
		}
	}

	fbr_buffer_ok(fbuf);

	if (buffer) {
		assert_dev(buffer_len);
		assert_zero_dev(fbuf->buffer_free);

		fbuf->buffer = buffer;
		fbuf->buffer_len = buffer_len;
	} else {
		fbuf->buffer = malloc(buffer_len);
		assert(fbuf->buffer);

		fbuf->buffer_len = buffer_len;
		fbuf->buffer_free = 1;

		fbr_fs_stat_add(&fs->stats.write_buffers);
	}

	if (!current) {
		*head = fbuf;
		return;
	} else {
		assert_zero_dev(scratch);
		current->next = fbuf;
	}
}

void
fbr_writer_init(struct fbr_fs *fs, struct fbr_request *request, struct fbr_writer *writer,
    int want_gzip)
{
	fbr_fs_ok(fs);
	assert(writer);

	fbr_ZERO(writer);
	writer->magic = FBR_WRITER_MAGIC;

	if (request) {
		fbr_request_ok(request);

		// TODO make these buffer sizes conigurable, make sure they fit in workspace
		char *buffer = fbr_workspace_alloc(request->workspace, FBR_DEFAULT_BUFLEN);
		size_t buffer_len = FBR_DEFAULT_BUFLEN;

		if (buffer) {
			_buffer_add(fs, writer, buffer, buffer_len, 1);
			assert_dev(writer->scratch);
		}

		buffer = fbr_workspace_rbuffer(request->workspace);
		buffer_len = fbr_workspace_rlen(request->workspace);

		if (buffer && buffer_len >= FBR_DEFAULT_BUFLEN) {
			if (buffer_len >= FBR_DEFAULT_BUFLEN * 2) {
				buffer_len -= FBR_DEFAULT_BUFLEN;
			} else if (buffer_len > FBR_DEFAULT_BUFLEN) {
				buffer_len = FBR_DEFAULT_BUFLEN;
			}

			fbr_workspace_ralloc(request->workspace, buffer_len);

			_buffer_add(fs, writer, buffer, buffer_len, 0);
			assert_dev(writer->final);
		} else if (buffer) {
			fbr_workspace_ralloc(request->workspace, 0);
		}
	}

	if (!writer->scratch) {
		_buffer_add(fs, writer, NULL, 0, 1);
	}
	if (!writer->final) {
		_buffer_add(fs, writer, NULL, 0, 0);
	}

	writer->want_gzip = want_gzip;

	fbr_writer_ok(writer);
}

static void
_buffers_free(struct fbr_buffer *fbuf)
{
	while (fbuf) {
		fbr_buffer_ok(fbuf);

		struct fbr_buffer *next = fbuf->next;

		if (fbuf->buffer_free) {
			free(fbuf->buffer);
		}

		int do_free = fbuf->do_free;

		fbr_ZERO(fbuf);

		if (do_free) {
			free(fbuf);
		}

		fbuf = next;
	}
}

void
fbr_writer_free(struct fbr_fs *fs, struct fbr_writer *writer)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);

	_buffers_free(writer->scratch);
	_buffers_free(writer->final);

	fbr_ZERO(writer);
}

static void
_scratch_reset(struct fbr_writer *writer)
{
	assert_dev(writer);
	assert_dev(writer->scratch);
	assert_zero_dev(writer->scratch->next);

	writer->scratch->buffer_pos = 0;
}

static void
_buffer_append(struct fbr_buffer *fbuf, const char *buffer, size_t buffer_len)
{
	assert_dev(fbuf);
	assert_dev(buffer);
	assert_dev(buffer_len);
	assert(fbuf->buffer_len - fbuf->buffer_pos >= buffer_len);

	memcpy(fbuf->buffer + fbuf->buffer_pos, buffer, buffer_len);
	fbuf->buffer_pos += buffer_len;

	assert(fbuf->buffer_len >= fbuf->buffer_pos);
}

static void
_add_final(struct fbr_fs *fs, struct fbr_writer *writer, const char *buffer, size_t buffer_len)
{
	assert_dev(fs);
	assert_dev(writer);
	assert_dev(writer->final);
	assert_dev(buffer);
	assert_dev(buffer_len);

	struct fbr_buffer *final = writer->final;
	while (final->next) {
		final = final->next;
	}

	size_t offset = 0;
	size_t size;

	// TODO compress

	while (offset < buffer_len) {
		fbr_buffer_ok(final);
		assert_dev(final->buffer_len >= final->buffer_pos);

		size_t final_free = final->buffer_len - final->buffer_pos;

		if (final_free) {
			size = buffer_len - offset;
			if (size > final_free) {
				size = final_free;
			}

			_buffer_append(final, buffer + offset, size);

			offset += size;
			assert_dev(offset <= buffer_len);

			continue;
		}

		assert_zero_dev(final->next);

		_buffer_add(fs, writer, NULL, 0, 0);

		final = final->next;
		assert_dev(final);
	}
}

static void
_copy_final(struct fbr_fs *fs, struct fbr_writer *writer)
{
	assert_dev(fs);
	assert_dev(writer);
	assert_dev(writer->scratch);
	assert_dev(writer->final);

	struct fbr_buffer *scratch = writer->scratch;
	fbr_buffer_ok(scratch);

	if (scratch->buffer_pos) {
		_add_final(fs, writer, scratch->buffer, scratch->buffer_pos);
	}

	_scratch_reset(writer);
}

void
fbr_writer_add(struct fbr_fs *fs, struct fbr_writer *writer, const char *buffer,
    size_t buffer_len)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);

	if (!buffer) {
		assert_zero_dev(buffer_len);
		_copy_final(fs, writer);
		return;
	}

	assert(buffer);
	assert(buffer_len);

	struct fbr_buffer *scratch = writer->scratch;
	fbr_buffer_ok(scratch);
	assert_dev(scratch->buffer_len);
	assert_dev(scratch->buffer_len >= scratch->buffer_pos);
	assert_zero_dev(scratch->next);

	size_t scratch_free = scratch->buffer_len - scratch->buffer_pos;

	if (buffer_len <= scratch_free) {
		_buffer_append(scratch, buffer, buffer_len);
	} else {
		_copy_final(fs, writer);
		assert_zero_dev(scratch->buffer_pos);

		if (buffer_len <= scratch->buffer_len) {
			_buffer_append(scratch, buffer, buffer_len);
		} else {
			_add_final(fs, writer, buffer, buffer_len);
		}
	}
}

void
fbr_writer_add_ulong(struct fbr_fs *fs, struct fbr_writer *writer, unsigned long value)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);

	struct fbr_buffer *scratch = writer->scratch;
	fbr_buffer_ok(scratch);
	assert_dev(scratch->buffer_len);
	assert_dev(scratch->buffer_len >= scratch->buffer_pos);

	size_t scratch_free = scratch->buffer_len - scratch->buffer_pos;

	if (scratch_free < 32) {
		_copy_final(fs, writer);

		scratch_free = scratch->buffer_len;
		assert_zero_dev(scratch->buffer_pos);
		assert(scratch_free >= 32);
	}

	int ret = snprintf(scratch->buffer + scratch->buffer_pos, scratch_free,
		"%lu", value);
	assert(ret > 0 && (size_t)ret < scratch_free);

	scratch->buffer_pos += ret;
}

void
fbr_writer_add_id(struct fbr_fs *fs, struct fbr_writer *writer, fbr_id_t id)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);

	struct fbr_buffer *scratch = writer->scratch;
	fbr_buffer_ok(scratch);
	assert_dev(scratch->buffer_len);
	assert_dev(scratch->buffer_len >= scratch->buffer_pos);

	size_t scratch_free = scratch->buffer_len - scratch->buffer_pos;

	if (scratch_free < FBR_ID_STRING_MAX) {
		_copy_final(fs, writer);

		scratch_free = scratch->buffer_len;
		assert_zero_dev(scratch->buffer_pos);
		assert(scratch_free >= FBR_ID_STRING_MAX);
	}

	size_t ret = fbr_id_string(id, scratch->buffer + scratch->buffer_pos, scratch_free);

	scratch->buffer_pos += ret;
}

static void
_buffer_debug(struct fbr_fs *fs, struct fbr_buffer *fbuf, const char *name)
{
	assert_dev(fs);
	assert_dev(fbuf);

	while (fbuf) {
		fbr_buffer_ok(fbuf);

		fs->log("WRITER %s pos: %zu len: %zu buf_free: %d free: %d", name,
			fbuf->buffer_pos, fbuf->buffer_len, fbuf->buffer_free, fbuf->do_free);

		fbuf = fbuf->next;
	}
}

void
fbr_writer_debug(struct fbr_fs *fs, struct fbr_writer *writer)
{
	fbr_fs_ok(fs);
	assert_dev(fs->logger);
	fbr_writer_ok(writer);

	_buffer_debug(fs, writer->scratch, "scratch");
	_buffer_debug(fs, writer->final, "final");

	fs->log("WRITER want_gzip: %d", writer->want_gzip);
	fs->log("WRITER is_gzip: %d", writer->is_gzip);
}
