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
_reader_init(struct fbr_reader *reader)
{
	assert_dev(reader);

	fbr_ZERO(reader);
	reader->magic = FBR_READER_MAGIC;
}

void
fbr_reader_init(struct fbr_fs *fs, struct fbr_reader *reader, struct fbr_request *request,
    int is_gzip)
{
	fbr_fs_ok(fs);
	assert(reader);

	_reader_init(reader);

	reader->was_gzip = is_gzip;

	if (request) {
		fbr_request_ok(request);

		char *buffer;
		size_t buffer_len;

		if (is_gzip) {
			// TODO make these buffer sizes conigurable
			buffer = fbr_workspace_alloc(request->workspace, FBR_DEFAULT_BUFLEN);
			buffer_len = FBR_DEFAULT_BUFLEN;

			if (buffer) {
				reader->buffer = &reader->_buffer;
				fbr_buffer_init(fs, reader->buffer, buffer, buffer_len);
			}
		}

		// TODO configurable
		buffer = fbr_workspace_alloc(request->workspace, FBR_DEFAULT_BUFLEN * 2);
		buffer_len = FBR_DEFAULT_BUFLEN * 2;

		if (buffer) {
			reader->output = &reader->_output;
			fbr_buffer_init(fs, reader->output, buffer, buffer_len);
		}
	}

	if (!reader->buffer && is_gzip) {
		reader->buffer = &reader->_buffer;
		fbr_buffer_init(fs, reader->buffer, NULL, FBR_DEFAULT_BUFLEN);
	}
	if (!reader->output) {
		reader->output = &reader->_output;
		fbr_buffer_init(fs, reader->output, NULL, FBR_DEFAULT_BUFLEN * 2);
	}

	fbr_reader_ok(reader);
}

void
fbr_reader_free(struct fbr_fs *fs, struct fbr_reader *reader)
{
	fbr_fs_ok(fs);
	fbr_reader_ok(reader);

	fbr_buffers_free(reader->buffer);
	fbr_buffers_free(reader->output);

	fbr_ZERO(reader);
}
