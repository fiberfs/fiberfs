/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_store.h"
#include "compress/fbr_gzip.h"
#include "core/request/fbr_request.h"

static void
_output_workspace_release(struct fbr_writer *writer)
{
	assert_dev(writer);
	assert_dev(writer->workspace);
	assert_dev(writer->output);
	assert_zero_dev(writer->output->next);

	fbr_workspace_ralloc(writer->workspace, writer->output->buffer_pos);
	assert(writer->output->buffer_pos);

	writer->output->buffer_len = writer->output->buffer_pos;
	writer->workspace = NULL;
}

static void
_writer_extend(struct fbr_fs *fs, struct fbr_writer *writer, char *buffer,
    size_t buffer_len, int alloc_buffer)
{
	assert_dev(fs);
	assert(writer);

	struct fbr_buffer **head = NULL;
	struct fbr_buffer *current = NULL;

	if (alloc_buffer) {
		assert_dev(writer->want_gzip);
		head = &writer->buffer;
		current = writer->buffer;
	} else {
		head = &writer->output;
		current = writer->output;

		if (current && writer->workspace) {
			_output_workspace_release(writer);
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

	int do_free = 0;

	if (!fbuf) {
		size_t buffer_alloc = 0;
		if (!buffer) {
			assert_dev(buffer_len);
			buffer_alloc = buffer_len;
		}

		fbuf = malloc(sizeof(*fbuf) + buffer_alloc);
		assert(fbuf);

		if (!buffer) {
			buffer = (char*)(fbuf + 1);
		}

		do_free = 1;

		fbr_fs_stat_add(&fs->stats.buffers);
	}

	fbr_buffer_init(fs, fbuf, buffer, buffer_len);
	fbr_buffer_ok(fbuf);

	fbuf->do_free = do_free;

	if (!current) {
		*head = fbuf;
		return;
	} else {
		assert_zero_dev(alloc_buffer);
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
				_writer_extend(fs, writer, buffer, buffer_len, 1);
				assert_dev(writer->buffer);
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

			_writer_extend(fs, writer, buffer, buffer_len, 0);
			assert_dev(writer->output);
		} else if (buffer) {
			fbr_workspace_ralloc(request->workspace, 0);
		}
	}

	if (!writer->buffer && want_gzip) {
		_writer_extend(fs, writer, NULL, 0, 1);
	}
	if (!writer->output) {
		_writer_extend(fs, writer, NULL, 0, 0);
	}

	fbr_writer_ok(writer);
}

void
fbr_writer_init_buffer(struct fbr_fs *fs, struct fbr_writer *writer, char *buffer,
    size_t buffer_len)
{
	fbr_fs_ok(fs);
	assert(writer);
	assert(buffer);
	assert(buffer_len);

	_writer_init(writer);
	_writer_extend(fs, writer, buffer, buffer_len, 0);
}

void
fbr_writer_free(struct fbr_fs *fs, struct fbr_writer *writer)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);
	assert_zero_dev(writer->workspace);

	if (writer->buffer) {
		assert_zero_dev(writer->buffer->buffer_pos);
		assert_zero_dev(writer->buffer->next);
	}

	fbr_buffers_free(writer->buffer);
	fbr_buffers_free(writer->output);

	if (writer->is_gzip) {
		fbr_gzip_free(&writer->gzip);
	}

	fbr_ZERO(writer);
}

static void
_output_compress(struct fbr_fs *fs, struct fbr_writer *writer, const char *buffer,
    size_t buffer_len, int final)
{
	assert_dev(fs);
	assert_dev(writer);
	assert_dev(writer->is_gzip);
	assert_dev(writer->output);
	assert_dev(buffer);
	assert_dev(buffer_len);

	if (writer->error) {
		return;
	}

	struct fbr_gzip *gzip = &writer->gzip;
	struct fbr_buffer *output = writer->output;
	while (output->next) {
		assert_zero_dev(writer->workspace);
		output = output->next;
	}

	do {
		fbr_buffer_ok(output);
		assert_dev(output->buffer_len >= output->buffer_pos);

		size_t output_free = output->buffer_len - output->buffer_pos;

		if (output_free) {
			size_t written;

			fbr_gzip_flate(gzip, (const unsigned char *)buffer, buffer_len,
				(unsigned char *)output->buffer + output->buffer_pos, output_free,
				&written, final);

			if (gzip->status == FBR_GZIP_ERROR) {
				writer->error = 1;
				return;
			}

			assert_dev(written <= output_free);
			output->buffer_pos += written;
			assert(output->buffer_len >= output->buffer_pos);

			buffer = NULL;
			buffer_len = 0;
		} else {
			assert_zero_dev(output->next);

			_writer_extend(fs, writer, NULL, 0, 0);

			output = output->next;
			assert_dev(output);
		}
	} while (gzip->status == FBR_GZIP_MORE_BUFFER);

	assert_dev(gzip->status == FBR_GZIP_DONE);
}

static void
_output_add(struct fbr_fs *fs, struct fbr_writer *writer, const char *buffer, size_t buffer_len,
    int final)
{
	assert_dev(fs);
	assert_dev(writer);
	assert_dev(writer->output);
	assert_dev(buffer);
	assert_dev(buffer_len);

	if (writer->want_gzip && fbr_gzip_enabled()) {
		if (!writer->is_gzip) {
			fbr_gzip_deflate_init(&writer->gzip);
			writer->is_gzip = 1;
		}

		_output_compress(fs, writer, buffer, buffer_len, final);

		return;
	}

	struct fbr_buffer *output = writer->output;
	while (output->next) {
		assert_zero_dev(writer->workspace);
		output = output->next;
	}

	size_t offset = 0;
	size_t size;

	while (offset < buffer_len) {
		fbr_buffer_ok(output);
		assert_dev(output->buffer_len >= output->buffer_pos);

		size_t output_free = output->buffer_len - output->buffer_pos;

		if (output_free) {
			size = buffer_len - offset;
			if (size > output_free) {
				size = output_free;
			}

			fbr_buffer_append(output, buffer + offset, size);

			offset += size;
			assert_dev(offset <= buffer_len);

			continue;
		}

		assert_zero_dev(output->next);

		_writer_extend(fs, writer, NULL, 0, 0);

		output = output->next;
		assert_dev(output);
	}
}

struct fbr_buffer *
_buffer_get(struct fbr_writer *writer)
{
	assert_dev(writer);

	struct fbr_buffer *output = writer->buffer;

	if (!output) {
		assert_dev(writer->output);
		output = writer->output;
	}

	while (output->next) {
		output = output->next;
	}

	fbr_buffer_ok(output);
	assert_dev(output->buffer_len);
	assert_dev(output->buffer_len >= output->buffer_pos);

	return output;
}

static void
_writer_flush(struct fbr_fs *fs, struct fbr_writer *writer, int final)
{
	assert_dev(fs);
	assert_dev(writer);
	assert_dev(writer->output);

	if (writer->buffer) {
		fbr_buffer_ok(writer->buffer);
		assert_zero_dev(writer->buffer->next);

		if (writer->buffer->buffer_pos) {
			_output_add(fs, writer, writer->buffer->buffer,
				writer->buffer->buffer_pos, final);

			writer->buffer->buffer_pos = 0;
		}
	}

	if (writer->workspace && final) {
		_output_workspace_release(writer);
	}

	writer->bytes = 0;

	struct fbr_buffer *output = writer->output;
	while (output) {
		fbr_buffer_ok(output);
		writer->bytes += output->buffer_pos;
		output = output->next;
	}
}

void
fbr_writer_flush(struct fbr_fs *fs, struct fbr_writer *writer)
{
	_writer_flush(fs, writer, 1);
}

static struct fbr_buffer *
_flush_extend(struct fbr_fs *fs, struct fbr_writer *writer)
{
	assert_dev(fs);
	assert_dev(writer);

	_writer_flush(fs, writer, 0);

	struct fbr_buffer *output = writer->buffer;

	if (!output) {
		output = _buffer_get(writer);
		if (output->buffer_pos) {
			_writer_extend(fs, writer, NULL, 0, 0);
			output = _buffer_get(writer);
		}
	}

	fbr_buffer_ok(output);
	assert_zero_dev(output->buffer_pos);

	return output;
}

void
fbr_writer_add(struct fbr_fs *fs, struct fbr_writer *writer, const char *buffer,
    size_t buffer_len)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);
	assert(buffer);
	assert(buffer_len);

	struct fbr_buffer *output = _buffer_get(writer);
	assert_dev(output);

	size_t output_free = output->buffer_len - output->buffer_pos;

	if (buffer_len <= output_free) {
		fbr_buffer_append(output, buffer, buffer_len);
	} else {
		output = _flush_extend(fs, writer);
		assert_dev(output);
		assert_zero_dev(output->buffer_pos);

		if (buffer_len <= output->buffer_len) {
			fbr_buffer_append(output, buffer, buffer_len);
		} else {
			_output_add(fs, writer, buffer, buffer_len, 0);
		}
	}

	writer->raw_bytes += buffer_len;
}

void
fbr_writer_add_ulong(struct fbr_fs *fs, struct fbr_writer *writer, unsigned long value)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);

	struct fbr_buffer *output = _buffer_get(writer);
	assert_dev(output);

	size_t output_free = output->buffer_len - output->buffer_pos;

	if (output_free < 32) {
		output = _flush_extend(fs, writer);
		assert_dev(output);
		assert_zero_dev(output->buffer_pos);

		output_free = output->buffer_len;
		assert(output_free >= 32);
	}

	int ret = snprintf(output->buffer + output->buffer_pos, output_free, "%lu", value);
	assert(ret > 0 && (size_t)ret < output_free);

	output->buffer_pos += ret;
	writer->raw_bytes += ret;
}

void
fbr_writer_add_id(struct fbr_fs *fs, struct fbr_writer *writer, fbr_id_t id)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);

	struct fbr_buffer *output = _buffer_get(writer);
	assert_dev(output);

	size_t output_free = output->buffer_len - output->buffer_pos;

	if (output_free < FBR_ID_STRING_MAX) {
		output = _flush_extend(fs, writer);
		assert_dev(output);
		assert_zero_dev(output->buffer_pos);

		output_free = output->buffer_len;
		assert(output_free >= FBR_ID_STRING_MAX);
	}

	size_t ret = fbr_id_string(id, output->buffer + output->buffer_pos, output_free);

	output->buffer_pos += ret;
	writer->raw_bytes += ret;
}

void
fbr_writer_debug(struct fbr_fs *fs, struct fbr_writer *writer)
{
	fbr_fs_ok(fs);
	assert_dev(fs->logger);
	fbr_writer_ok(writer);

	fbr_buffer_debug(fs, writer->buffer, "buffer");
	fbr_buffer_debug(fs, writer->output, "output");

	fs->log("WRITER workspace: %s", writer->workspace ? "true" : "false");
	fs->log("WRITER raw_bytes: %zu", writer->raw_bytes);
	fs->log("WRITER bytes: %zu", writer->bytes);
	fs->log("WRITER want_gzip: %d", writer->want_gzip);
	fs->log("WRITER is_gzip: %d", writer->is_gzip);
}
