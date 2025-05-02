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
_buffer_workspace_release(struct fbr_writer *writer)
{
	assert_dev(writer);
	assert_dev(writer->workspace);
	assert_dev(writer->buffers)
	assert_zero_dev(writer->buffers->next);

	fbr_workspace_ralloc(writer->workspace, writer->buffers->buffer_pos);

	writer->buffers->buffer_len = writer->buffers->buffer_pos;
	writer->workspace = NULL;
}

static void
_buffer_extend(struct fbr_fs *fs, struct fbr_writer *writer, char *buffer,
    size_t buffer_len, int pre_buffer)
{
	assert_dev(fs);
	assert(writer);

	struct fbr_buffer **head = NULL;
	struct fbr_buffer *current = NULL;

	if (pre_buffer) {
		assert_dev(writer->want_gzip);
		head = &writer->pre_buffer;
		current = writer->pre_buffer;
	} else {
		head = &writer->buffers;
		current = writer->buffers;

		if (current && writer->workspace) {
			_buffer_workspace_release(writer);
		}
	}
	while (current && current->next) {
		current = current->next;
	}

	if (!buffer) {
		assert_zero_dev(buffer_len);
		buffer_len = FBR_DEFAULT_BUFLEN;
		while (current && buffer_len < (current->buffer_len * 2)) {
			buffer_len *= 2;
		}
	}

	struct fbr_buffer *fbuf = NULL;

	for (size_t i = 0; i < fbr_array_len(writer->buffer_slab); i++) {
		if (!writer->buffer_slab[i].magic) {
			fbuf = &writer->buffer_slab[i];
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
		assert_zero_dev(pre_buffer);
		current->next = fbuf;
	}
}

static void
_writer_init(struct fbr_writer *writer)
{
	assert_dev(writer);

	fbr_ZERO(writer);
	writer->magic = FBR_WRITER_MAGIC;
}

void
fbr_writer_init(struct fbr_fs *fs, struct fbr_writer *writer, struct fbr_request *request,
    int want_gzip)
{
	fbr_fs_ok(fs);
	assert(writer);

	_writer_init(writer);

	writer->want_gzip = want_gzip;

	if (request) {
		fbr_request_ok(request);

		char *buffer;
		size_t buffer_len;

		if (want_gzip) {
			// TODO make these buffer sizes conigurable
			buffer = fbr_workspace_alloc(request->workspace, FBR_DEFAULT_BUFLEN);
			buffer_len = FBR_DEFAULT_BUFLEN;

			if (buffer) {
				_buffer_extend(fs, writer, buffer, buffer_len, 1);
				assert_dev(writer->pre_buffer);
			}
		}

		buffer = fbr_workspace_rbuffer(request->workspace);
		buffer_len = fbr_workspace_rlen(request->workspace);

		if (buffer && buffer_len >= FBR_DEFAULT_BUFLEN) {
			if (buffer_len >= FBR_DEFAULT_BUFLEN * 2) {
				buffer_len -= FBR_DEFAULT_BUFLEN;
			} else if (buffer_len > FBR_DEFAULT_BUFLEN) {
				buffer_len = FBR_DEFAULT_BUFLEN;
			}

			writer->workspace = request->workspace;

			_buffer_extend(fs, writer, buffer, buffer_len, 0);
			assert_dev(writer->buffers);
		} else if (buffer) {
			fbr_workspace_ralloc(request->workspace, 0);
		}
	}

	if (!writer->pre_buffer && want_gzip) {
		_buffer_extend(fs, writer, NULL, 0, 1);
	}
	if (!writer->buffers) {
		_buffer_extend(fs, writer, NULL, 0, 0);
	}

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
	assert_zero_dev(writer->workspace);

	if (writer->pre_buffer) {
		assert_zero_dev(writer->pre_buffer->buffer_pos);
	}

	_buffers_free(writer->pre_buffer);
	_buffers_free(writer->buffers);

	fbr_ZERO(writer);
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
_buffers_add(struct fbr_fs *fs, struct fbr_writer *writer, const char *buffer, size_t buffer_len)
{
	assert_dev(fs);
	assert_dev(writer);
	assert_dev(writer->buffers);
	assert_dev(buffer);
	assert_dev(buffer_len);

	struct fbr_buffer *fbuf = writer->buffers;
	while (fbuf->next) {
		assert_zero_dev(writer->workspace);
		fbuf = fbuf->next;
	}

	size_t offset = 0;
	size_t size;

	if (writer->want_gzip) {
		// TODO compress
	}

	while (offset < buffer_len) {
		fbr_buffer_ok(fbuf);
		assert_dev(fbuf->buffer_len >= fbuf->buffer_pos);

		size_t fbuf_free = fbuf->buffer_len - fbuf->buffer_pos;

		if (fbuf_free) {
			size = buffer_len - offset;
			if (size > fbuf_free) {
				size = fbuf_free;
			}

			_buffer_append(fbuf, buffer + offset, size);

			offset += size;
			assert_dev(offset <= buffer_len);

			continue;
		}

		assert_zero_dev(fbuf->next);

		_buffer_extend(fs, writer, NULL, 0, 0);

		fbuf = fbuf->next;
		assert_dev(fbuf);
	}

	// TODO final bytes here
	writer->bytes += buffer_len;
}

struct fbr_buffer *
_buffer_get(struct fbr_writer *writer)
{
	assert_dev(writer);

	struct fbr_buffer *fbuf = writer->pre_buffer;

	if (!fbuf) {
		assert_dev(writer->buffers);
		fbuf = writer->buffers;
	}

	while (fbuf->next) {
		fbuf = fbuf->next;
	}

	fbr_buffer_ok(fbuf);
	assert_dev(fbuf->buffer_len);
	assert_dev(fbuf->buffer_len >= fbuf->buffer_pos);

	return fbuf;
}

void
fbr_writer_flush(struct fbr_fs *fs, struct fbr_writer *writer)
{
	assert_dev(fs);
	assert_dev(writer);
	assert_dev(writer->buffers);

	if (writer->pre_buffer) {
		fbr_buffer_ok(writer->pre_buffer);

		if (writer->pre_buffer->buffer_pos) {
			_buffers_add(fs, writer, writer->pre_buffer->buffer,
				writer->pre_buffer->buffer_pos);

			writer->pre_buffer->buffer_pos = 0;
		}
	}

	if (writer->workspace) {
		_buffer_workspace_release(writer);
	}

	writer->bytes = 0;

	struct fbr_buffer *fbuf = writer->buffers;
	while (fbuf) {
		fbr_buffer_ok(fbuf);
		writer->bytes += fbuf->buffer_pos;
		fbuf = fbuf->next;
	}
}

static struct fbr_buffer *
_flush_extend(struct fbr_fs *fs, struct fbr_writer *writer)
{
	assert_dev(fs);
	assert_dev(writer);

	fbr_writer_flush(fs, writer);

	struct fbr_buffer *fbuf = writer->pre_buffer;

	if (!fbuf) {
		_buffer_extend(fs, writer, NULL, 0, 0);
		fbuf = _buffer_get(writer);
	}

	fbr_buffer_ok(fbuf);
	assert_zero_dev(fbuf->buffer_pos);

	return fbuf;
}

void
fbr_writer_add(struct fbr_fs *fs, struct fbr_writer *writer, const char *buffer,
    size_t buffer_len)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);
	assert(buffer);
	assert(buffer_len);

	struct fbr_buffer *fbuf = _buffer_get(writer);
	assert_dev(fbuf);

	size_t fbuf_free = fbuf->buffer_len - fbuf->buffer_pos;

	if (buffer_len <= fbuf_free) {
		_buffer_append(fbuf, buffer, buffer_len);
	} else {
		fbuf = _flush_extend(fs, writer);
		assert_dev(fbuf);
		assert_zero_dev(fbuf->buffer_pos);

		if (buffer_len <= fbuf->buffer_len) {
			_buffer_append(fbuf, buffer, buffer_len);
		} else {
			_buffers_add(fs, writer, buffer, buffer_len);
		}
	}

	writer->raw_bytes += buffer_len;
}

void
fbr_writer_add_ulong(struct fbr_fs *fs, struct fbr_writer *writer, unsigned long value)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);

	struct fbr_buffer *fbuf = _buffer_get(writer);
	assert_dev(fbuf);

	size_t fbuf_free = fbuf->buffer_len - fbuf->buffer_pos;

	if (fbuf_free < 32) {
		fbuf = _flush_extend(fs, writer);
		assert_dev(fbuf);
		assert_zero_dev(fbuf->buffer_pos);

		fbuf_free = fbuf->buffer_len;
		assert(fbuf_free >= 32);
	}

	int ret = snprintf(fbuf->buffer + fbuf->buffer_pos, fbuf_free, "%lu", value);
	assert(ret > 0 && (size_t)ret < fbuf_free);

	fbuf->buffer_pos += ret;
	writer->raw_bytes += ret;
}

void
fbr_writer_add_id(struct fbr_fs *fs, struct fbr_writer *writer, fbr_id_t id)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);

	struct fbr_buffer *fbuf = _buffer_get(writer);
	assert_dev(fbuf);

	size_t fbuf_free = fbuf->buffer_len - fbuf->buffer_pos;

	if (fbuf_free < FBR_ID_STRING_MAX) {
		fbuf = _flush_extend(fs, writer);
		assert_dev(fbuf);
		assert_zero_dev(fbuf->buffer_pos);

		fbuf_free = fbuf->buffer_len;
		assert(fbuf_free >= FBR_ID_STRING_MAX);
	}

	size_t ret = fbr_id_string(id, fbuf->buffer + fbuf->buffer_pos, fbuf_free);

	fbuf->buffer_pos += ret;
	writer->raw_bytes += ret;
}

static void
_buffer_debug(struct fbr_fs *fs, struct fbr_buffer *fbuf, const char *name)
{
	assert_dev(fs);

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

	_buffer_debug(fs, writer->pre_buffer, "pre_buffer");
	_buffer_debug(fs, writer->buffers, "buffers");

	fs->log("WRITER raw_bytes: %zu", writer->raw_bytes);
	fs->log("WRITER bytes: %zu", writer->bytes);
	fs->log("WRITER want_gzip: %d", writer->want_gzip);
	fs->log("WRITER is_gzip: %d", writer->is_gzip);
}
