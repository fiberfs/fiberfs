/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_store.h"

void
fbr_buffer_init(struct fbr_fs *fs, struct fbr_buffer *fbuf, char *buffer, size_t buffer_len)
{
	fbr_fs_ok(fs);
	assert(fbuf);
	assert(buffer_len);

	fbr_ZERO(fbuf);
	fbuf->magic = FBR_BUFFER_MAGIC;

	if (!buffer) {
		buffer = malloc(buffer_len);
		assert(buffer);

		fbuf->buffer_free = 1;

		fbr_fs_stat_add(&fs->stats.buffers);
	}

	fbuf->buffer = buffer;
	fbuf->buffer_len = buffer_len;
}

void
fbr_buffer_append(struct fbr_buffer *output, const char *buffer, size_t buffer_len)
{
	fbr_buffer_ok(output);
	assert(buffer);
	assert(buffer_len);
	assert(output->buffer_len - output->buffer_pos >= buffer_len);

	memcpy(output->buffer + output->buffer_pos, buffer, buffer_len);
	output->buffer_pos += buffer_len;

	assert(output->buffer_len >= output->buffer_pos);
}

void
fbr_buffers_free(struct fbr_buffer *fbuf)
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
fbr_buffer_debug(struct fbr_fs *fs, struct fbr_buffer *fbuf, const char *name)
{
	fbr_fs_ok(fs);

	size_t i = 0;

	while (fbuf) {
		fbr_buffer_ok(fbuf);

		fs->log("WRITER %s.%zu pos: %zu len: %zu buf_free: %d free: %d", name, i,
			fbuf->buffer_pos, fbuf->buffer_len, fbuf->buffer_free, fbuf->do_free);

		fbuf = fbuf->next;
		i++;
	}
}
