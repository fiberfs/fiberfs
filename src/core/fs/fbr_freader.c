/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

// TODO
#include <stdio.h>

#include "fiberfs.h"
#include "fbr_fs.h"

static uint8_t _ZERO_FILL[1024 * 8];

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
_freader_retain_add(struct fbr_freader *reader, struct fbr_chunk *chunk)
{
	fbr_freader_ok(reader);
	fbr_chunk_ok(chunk);

	for (size_t i = 0; i < fbr_static_array_len(reader->retain); i++) {
		if (!reader->retain[i]) {
			reader->retain[i] = chunk;
			return;
		}
	}

	fbr_chunk_release(chunk);
}

static void
_freader_retain_release(struct fbr_freader *reader)
{
	fbr_freader_ok(reader);

	for (size_t i = 0; i < fbr_static_array_len(reader->retain); i++) {
		if (reader->retain[i]) {
			struct fbr_chunk *chunk = reader->retain[i];
			fbr_chunk_ok(chunk);
			fbr_chunk_release(chunk);
			reader->retain[i] = NULL;
		}
	}
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

	_freader_retain_release(reader);

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

static struct iovec *
_freader_iovec_get(struct fbr_freader *reader)
{
	fbr_freader_ok(reader);

	if (reader->iovec_pos == reader->iovec_len) {
		_freader_iovec_expand(reader);
	}
	assert_dev(reader->iovec_pos < reader->iovec_len);

	struct iovec *io = &reader->iovec[reader->iovec_pos];

	return io;
}

static void
_freader_iovec_zero(struct fbr_freader *reader, size_t length)
{
	fbr_freader_ok(reader);

	while (length) {
		size_t zero_length = length;
		if (zero_length > sizeof(_ZERO_FILL)) {
			zero_length = sizeof(_ZERO_FILL);
		}

		struct iovec *io = _freader_iovec_get(reader);

		io->iov_base = _ZERO_FILL;
		io->iov_len = zero_length;

		reader->iovec_pos++;
		length -= zero_length;
	}
}

static struct fbr_chunk *
_freader_find_next_chunk(struct fbr_freader *reader, size_t offset)
{
	fbr_freader_ok(reader);

	struct fbr_chunk *closest = NULL;
	size_t closest_distance = 0;

	for (size_t i = 0; i < reader->chunks_pos; i++) {
		struct fbr_chunk *chunk = reader->chunks[i];
		fbr_chunk_ok(chunk);

		// chunk is before or at offset
		if (chunk->offset <= offset) {
			continue;
		}

		size_t chunk_distance = chunk->offset - offset;

		if (!closest || chunk_distance < closest_distance) {
			closest = chunk;
			closest_distance = chunk_distance;
		}
	}

	return closest;
}

static struct fbr_chunk *
_freader_find_chunk(struct fbr_freader *reader, size_t offset)
{
	fbr_freader_ok(reader);

	for (size_t i = 0; i < reader->chunks_pos; i++) {
		struct fbr_chunk *chunk = reader->chunks[i];
		fbr_chunk_ok(chunk);

		size_t chunk_end = chunk->offset + chunk->length;

		// chunk covers offset
		if (chunk->offset <= offset && chunk_end > offset) {
			return chunk;
		}
	}

	return NULL;
}

void
fbr_freader_iovec_gen(struct fbr_fs *fs, struct fbr_freader *reader, size_t offset, size_t size)
{
	fbr_fs_ok(fs);
	fbr_freader_ok(reader);
	assert(reader->iovec_len);

	reader->iovec_pos = 0;

	size_t offset_end = offset + size;
	size_t offset_pos = offset;

	while (offset_pos < offset_end) {
		struct fbr_chunk *chunk = _freader_find_chunk(reader, offset_pos);

		if (!chunk) {
			// Fill with the zero page
			chunk = _freader_find_next_chunk(reader, offset_pos);

			size_t zero_fill_length = offset_end - offset_pos;

			if (chunk) {
				fbr_chunk_ok(chunk);
				assert(chunk->offset > offset_pos);
				zero_fill_length = chunk->offset - offset_pos;
			}

			_freader_iovec_zero(reader, zero_fill_length);

			offset_pos += zero_fill_length;

			if (!chunk) {
				continue;
			}
		}

		fbr_chunk_ok(chunk);
		assert(chunk->state == FBR_CHUNK_READY);
		assert(chunk->data);

		size_t chunk_offset = 0;
		if (chunk->offset < offset_pos) {
			chunk_offset = offset_pos - chunk->offset;
			assert(chunk_offset < chunk->length);
		}

		size_t chunk_length = chunk->length - chunk_offset;
		if (chunk_length > offset_end - offset_pos) {
			chunk_length = offset_end - offset_pos;
		}

		struct fbr_chunk *chunk_next = _freader_find_next_chunk(reader, offset_pos);

		if (chunk_next) {
			fbr_chunk_ok(chunk_next);
			assert(chunk_next->offset > offset_pos);

			if (chunk_length > chunk_next->offset - offset_pos) {
				chunk_length = chunk_next->offset - offset_pos;
			}
		}

		// Can we merge into the last iovec?
		if (chunk_offset && reader->iovec_pos) {
			struct iovec *io_last = &reader->iovec[reader->iovec_pos - 1];

			if (io_last->iov_base == chunk->data &&
			    io_last->iov_len == chunk_offset) {
				io_last->iov_len += chunk_length;
				assert_dev(io_last->iov_len <= chunk->length);

				offset_pos += chunk_length;

				continue;
			}
		}

		struct iovec *io = _freader_iovec_get(reader);

		io->iov_base = chunk->data + chunk_offset;
		io->iov_len = chunk_length;

		reader->iovec_pos++;
		offset_pos += chunk_length;
	}

	assert_dev(offset_pos == offset_end);

	if (fbr_assert_is_dev()) {
		/*
		for (size_t i = 0; i < reader->chunks_pos; i++) {
			struct fbr_chunk *chunk = reader->chunks[i];
			fbr_chunk_ok(chunk);
			printf("ZZZ chunks[%zu].data = %p\n", i, (void*)chunk->data);
			printf("ZZZ chunks[%zu].offset = %zu\n", i, chunk->offset);
			printf("ZZZ chunks[%zu].length = %zu\n", i, chunk->length);
		}
		*/
		size_t total_size = 0;
		for (size_t i = 0; i < reader->iovec_pos; i++) {
			struct iovec *io = &reader->iovec[i];
			/*
			printf("ZZZ iovec[%zu].iov_base = %p\n", i, (void*)io->iov_base);
			printf("ZZZ iovec[%zu].iov_len = %zu\n", i, io->iov_len);
			*/
			total_size += io->iov_len;
		}
		assert(total_size == size);
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
			_freader_retain_add(reader, chunk);
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
	fbr_file_ok(reader->file);

	assert_zero(pthread_mutex_lock(&reader->file->body.lock));
	_freader_retain_release(reader);
	assert_zero(pthread_mutex_unlock(&reader->file->body.lock));

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
