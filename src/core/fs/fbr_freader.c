/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_fs.h"

struct fbr_freader *
fbr_freader_alloc(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	struct fbr_freader *reader = calloc(1, sizeof(*reader));
	assert(reader);

	reader->magic = FBR_FREADER_MAGIC;
	reader->file = file;

	reader->chunks = reader->_chunks;
	reader->chunks_len = FBR_BODY_DEFAULT_CHUNKS;

	return reader;
}

static void
_freader_chunk_add(struct fbr_freader *reader, struct fbr_chunk *chunk)
{
	fbr_freader_ok(reader);
	fbr_chunk_ok(chunk);
	assert(reader->chunks_len);
	assert(reader->chunks_pos < 1000 * 10);

	if (reader->chunks_pos >= reader->chunks_len) {
		if (reader->chunks_len < FBR_BODY_SLAB_DEFAULT_CHUNKS) {
			reader->chunks_len = FBR_BODY_SLAB_DEFAULT_CHUNKS;
		} else {
			reader->chunks_len *= 2;
		}

		if (reader->chunks == reader->_chunks) {
			reader->chunks = malloc(sizeof(*reader->chunks) * reader->chunks_len);
			assert(reader->chunks);

			memcpy(reader->chunks, reader->_chunks,
				sizeof(*reader->chunks) * FBR_BODY_DEFAULT_CHUNKS);
		} else {
			reader->chunks_len *= 2;
			reader->chunks = realloc(reader->chunks,
				sizeof(*reader->chunks) * reader->chunks_len);
			assert(reader->chunks);
		}
	}

	assert_dev(reader->chunks_pos < reader->chunks_len);

	reader->chunks[reader->chunks_pos] = chunk;
	reader->chunks_pos++;
}

static int
_freader_ready_error(struct fbr_freader *reader)
{
	fbr_freader_ok(reader);

	for (size_t i = 0; i < reader->chunks_pos; i++) {
		struct fbr_chunk *chunk = reader->chunks[i];
		fbr_chunk_ok(chunk);

		if (chunk->state == FBR_CHUNK_UNREAD) {
			return 1;
		}
	}

	return 0;
}

static int
_freader_ready(struct fbr_freader *reader)
{
	fbr_freader_ok(reader);

	for (size_t i = 0; i < reader->chunks_pos; i++) {
		struct fbr_chunk *chunk = reader->chunks[i];
		fbr_chunk_ok(chunk);

		if (chunk->state != FBR_CHUNK_READ) {
			return 0;
		}
	}

	return 1;
}

void
fbr_freader_pull_chunks(struct fbr_fs *fs, struct fbr_freader *reader, size_t offset,
    size_t size)
{
	fbr_fs_ok(fs);
	fbr_freader_ok(reader);
	fbr_file_ok(reader->file);
	assert_zero(reader->chunks_pos);

	reader->error = 0;

	struct fbr_body *body = &reader->file->body;
	size_t offset_end = offset + size;

	assert_zero(pthread_mutex_lock(&body->lock));

	struct fbr_chunk *chunk = body->chunks;

	while (chunk) {
		fbr_chunk_ok(chunk);
		assert(chunk->state >= FBR_CHUNK_UNREAD);

		size_t chunk_end = chunk->offset + chunk->length;

		// offset starts in chunk || offset ends in chunk
		if ((offset >= chunk->offset && offset < chunk_end) ||
		    (offset < chunk->offset && offset_end >= chunk->offset)) {
			fbr_chunk_take(chunk);
			_freader_chunk_add(reader, chunk);

			if (chunk->state == FBR_CHUNK_UNREAD) {
				if (fs->fs_chunk_cb) {
					fs->fs_chunk_cb(fs, reader->file, chunk);
				}
			}
		} else if (chunk->offset > offset_end) {
			break;
		}

		chunk = chunk->next;
	}

	while (!_freader_ready(reader)) {
		if (_freader_ready_error(reader)) {
			reader->error = 1;
			break;
		}

		pthread_cond_wait(&body->update, &body->lock);
	}

	assert_zero(pthread_mutex_unlock(&body->lock));
}

size_t
fbr_freader_copy_chunks(struct fbr_fs *fs, struct fbr_freader *reader, char *buffer,
    size_t offset, size_t buffer_len)
{
	fbr_fs_ok(fs);
	fbr_freader_ok(reader);
	fbr_file_ok(reader->file);
	assert(buffer);
	assert(buffer_len);

	if (offset >= reader->file->size) {
		return 0;
	}

	size_t offset_end = offset + buffer_len;

	for (size_t i = 0; i < reader->chunks_pos; i++) {
		struct fbr_chunk *chunk = reader->chunks[i];
		fbr_chunk_ok(chunk);

		size_t chunk_end = chunk->offset + chunk->length;

		// offset in chunk
		if (offset >= chunk->offset && offset < chunk_end) {
			size_t chunk_offset = offset - chunk->offset;
			assert_dev(chunk->length > chunk_offset);

			size_t chunk_len = chunk->length - chunk_offset;
			if (chunk_len > buffer_len) {
				chunk_len = buffer_len;
			}

			memcpy(buffer, chunk->data + chunk_offset, chunk_len);
		}
		// offset sits before chunk (and hits chunk)
		else if (offset < chunk->offset && offset_end >= chunk->offset) {
			size_t buffer_offset = chunk->offset - offset;
			assert_dev(buffer_len > buffer_offset);

			size_t chunk_len = buffer_len - buffer_offset;
			if (chunk_len > chunk->length) {
				chunk_len = chunk->length;
			}

			memcpy(buffer + buffer_offset, chunk->data, chunk_len);
		}
	}

	if (offset_end > reader->file->size) {
		return reader->file->size - offset;
	}

	return buffer_len;
}

void
fbr_freader_release_chunks(struct fbr_fs *fs, struct fbr_freader *reader, size_t offset,
    size_t size)
{
	fbr_fs_ok(fs);
	fbr_freader_ok(reader);
	fbr_file_ok(reader->file);

	struct fbr_body *body = &reader->file->body;
	size_t offset_end = offset + size;

	assert_zero(pthread_mutex_lock(&body->lock));

	for (size_t i = 0; i < reader->chunks_pos; i++) {
		struct fbr_chunk *chunk = reader->chunks[i];
		fbr_chunk_ok(chunk);

		size_t chunk_end = chunk->offset + chunk->length;

		if (chunk_end >= offset_end) {
			fbr_chunk_release(chunk);
			// TODO we want to save these in our prefetch list
		} else {
			fbr_chunk_release(chunk);
		}

		reader->chunks[i] = NULL;
	}

	assert_zero(pthread_mutex_unlock(&body->lock));

	reader->chunks_pos = 0;
}

void
fbr_freader_free(struct fbr_fs *fs, struct fbr_freader *reader)
{
	fbr_fs_ok(fs);
	fbr_freader_ok(reader);

	fbr_inode_release(fs, &reader->file);
	assert_zero_dev(reader->file);

	if (reader->chunks != reader->_chunks) {
		free(reader->chunks);
	}

	fbr_ZERO(reader);

	free(reader);
}
