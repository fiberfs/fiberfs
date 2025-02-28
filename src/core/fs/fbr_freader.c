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
	reader->chunks_len = fbr_static_array_len(reader->_chunks);

	reader->iovec = reader->_iovec;
	reader->iovec_len = fbr_static_array_len(reader->_iovec);

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

			memcpy(reader->chunks, reader->_chunks, sizeof(reader->_chunks));
		} else {
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

		if (chunk->state == FBR_CHUNK_EMPTY) {
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

		if (chunk->state != FBR_CHUNK_READY) {
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
		assert(chunk->state >= FBR_CHUNK_EMPTY);

		size_t chunk_end = chunk->offset + chunk->length;

		// offset starts in chunk || offset ends in chunk
		if ((offset >= chunk->offset && offset < chunk_end) ||
		    (offset < chunk->offset && offset_end >= chunk->offset)) {
			fbr_chunk_take(chunk);
			_freader_chunk_add(reader, chunk);

			if (chunk->state == FBR_CHUNK_EMPTY) {
				if (fs->fetcher) {
					fs->fetcher(fs, reader->file, chunk);
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

static void
_freader_iovec_expand(struct fbr_freader *reader)
{
	fbr_freader_ok(reader);
	assert(reader->iovec_pos == reader->iovec_len);
	assert(reader->iovec_len);
	assert(reader->iovec_len < 1000 * 10);

	if (reader->iovec_len < FBR_BODY_SLAB_DEFAULT_CHUNKS) {
		reader->iovec_len = FBR_BODY_SLAB_DEFAULT_CHUNKS;
	} else {
		reader->iovec_len *= 2;
	}

	if (reader->iovec == reader->_iovec) {
		reader->iovec = malloc(sizeof(*reader->iovec) * reader->iovec_len);
		assert(reader->iovec);

		memcpy(reader->iovec, reader->_iovec, sizeof(reader->_iovec));
	} else {
		reader->iovec = realloc(reader->iovec,
			sizeof(*reader->iovec) * reader->iovec_len);
		assert(reader->iovec);
	}

	assert_dev(reader->iovec_pos < reader->iovec_len);
}

void
fbr_freader_gen_iovec(struct fbr_fs *fs, struct fbr_freader *reader)
{
	fbr_fs_ok(fs);
	fbr_freader_ok(reader);
	assert(reader->iovec_len);

	reader->iovec_pos = 0;

	for (size_t i = 0; i < reader->chunks_pos; i++) {
		struct fbr_chunk *chunk = reader->chunks[i];
		fbr_chunk_ok(chunk);
		assert(chunk->state == FBR_CHUNK_READY);

		if (reader->iovec_pos == reader->iovec_len) {
			_freader_iovec_expand(reader);
		}
		assert_dev(reader->iovec_pos < reader->iovec_len);

		struct iovec *io = &reader->iovec[reader->iovec_pos];

		io->iov_base = chunk->data;
		io->iov_len = chunk->length;

		reader->iovec_pos++;
	}
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

	if (reader->iovec != reader->_iovec) {
		free(reader->iovec);
	}

	fbr_ZERO(reader);

	free(reader);
}
