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
#include "core/store/fbr_store.h"

static uint8_t _ZERO_FILL[1024 * 16];

struct fbr_fio *
fbr_fio_alloc(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	struct fbr_fio *fio = calloc(1, sizeof(*fio));
	assert(fio);

	fio->magic = FBR_FIO_MAGIC;
	fio->file = file;

	fio->chunks = fio->_chunks;
	fio->chunks_len = fbr_array_len(fio->_chunks);

	fio->iovec = fio->_iovec;
	fio->iovec_len = fbr_array_len(fio->_iovec);

	return fio;
}

static void
_fio_expand_chunks(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);
	assert(fio->chunks_len);
	assert(fio->chunks_pos < 1000 * 10);

	if (fio->chunks_pos < fio->chunks_len) {
		return;
	}

	assert_dev(fio->chunks_pos == fio->chunks_len);

	if (fio->chunks_len < FBR_BODY_SLAB_DEFAULT_CHUNKS) {
		fio->chunks_len = FBR_BODY_SLAB_DEFAULT_CHUNKS;
	} else {
		fio->chunks_len *= 2;
	}

	if (fio->chunks == fio->_chunks) {
		fio->chunks = malloc(sizeof(*fio->chunks) * fio->chunks_len);
		assert(fio->chunks);

		memcpy(fio->chunks, fio->_chunks, sizeof(fio->_chunks));
	} else {
		fio->chunks = realloc(fio->chunks,
			sizeof(*fio->chunks) * fio->chunks_len);
		assert(fio->chunks);
	}
}

static void
_fio_release_chunks(struct fbr_fio *fio, size_t keep_offset)
{
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);

	size_t keep_chunks = 0;

	for (size_t i = 0; i < fio->chunks_pos; i++) {
		struct fbr_chunk *chunk = fio->chunks[i];
		fbr_chunk_ok(chunk);

		size_t chunk_end = chunk->offset + chunk->length;

		if (keep_offset && chunk_end >= keep_offset) {
			assert_dev(chunk->offset < keep_offset);
			if (i > keep_chunks) {
				fio->chunks[keep_chunks] = chunk;
				fio->chunks[i] = NULL;
			}
			keep_chunks++;
		} else {
			fbr_chunk_release(chunk);
			fio->chunks[i] = NULL;
		}
	}

	fio->chunks_pos = keep_chunks;
}

static void
_fio_chunk_add(struct fbr_fio *fio, struct fbr_chunk *chunk)
{
	fbr_fio_ok(fio);
	fbr_chunk_ok(chunk);

	struct fbr_chunk *swap_last = NULL;

	for (size_t i = 0; i < fio->chunks_pos; i++) {
		if (fio->chunks[i] == chunk) {
			swap_last = chunk;
		} else if (swap_last) {
			assert_dev(i);
			fio->chunks[i - 1] = fio->chunks[i];
			fio->chunks[i] = swap_last;
		}
	}

	if (swap_last) {
		return;
	}

	_fio_expand_chunks(fio);
	assert_dev(fio->chunks_pos < fio->chunks_len);

	fbr_chunk_take(chunk);

	fio->chunks[fio->chunks_pos] = chunk;
	fio->chunks_pos++;
}

static int
_fio_ready_error(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);

	for (size_t i = 0; i < fio->chunks_pos; i++) {
		struct fbr_chunk *chunk = fio->chunks[i];
		fbr_chunk_ok(chunk);

		if (chunk->state == FBR_CHUNK_EMPTY) {
			return 1;
		}
	}

	return 0;
}

static int
_fio_ready(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);

	for (size_t i = 0; i < fio->chunks_pos; i++) {
		struct fbr_chunk *chunk = fio->chunks[i];
		fbr_chunk_ok(chunk);

		if (chunk->state != FBR_CHUNK_READY) {
			return 0;
		}
	}

	return 1;
}

void
fbr_fio_pull_chunks(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset,
    size_t size)
{
	fbr_fs_ok(fs);
	assert(fs->store);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);

	fio->error = 0;

	struct fbr_body *body = &fio->file->body;
	size_t offset_end = offset + size;

	fbr_body_LOCK(body);

	_fio_release_chunks(fio, offset);

	struct fbr_chunk *chunk = body->chunks;

	while (chunk) {
		fbr_chunk_ok(chunk);
		assert(chunk->state >= FBR_CHUNK_EMPTY);

		size_t chunk_end = chunk->offset + chunk->length;

		// offset starts in chunk || offset ends in chunk
		if ((offset >= chunk->offset && offset < chunk_end) ||
		    (offset < chunk->offset && offset_end >= chunk->offset)) {
			_fio_chunk_add(fio, chunk);

			if (chunk->state == FBR_CHUNK_EMPTY) {
				if (fs->store->fetch_chunk_f) {
					fs->store->fetch_chunk_f(fs, fio->file, chunk);
				}
			}
		} else if (chunk->offset > offset_end) {
			break;
		}

		chunk = chunk->next;
	}

	while (!_fio_ready(fio)) {
		if (_fio_ready_error(fio)) {
			fio->error = 1;
			break;
		}

		pthread_cond_wait(&body->update, &body->lock);
	}

	fbr_body_UNLOCK(body);
}

static void
_fio_iovec_expand(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);
	assert(fio->iovec_pos == fio->iovec_len);
	assert(fio->iovec_len);
	assert(fio->iovec_len < 1000 * 10);

	if (fio->iovec_len < FBR_BODY_SLAB_DEFAULT_CHUNKS) {
		fio->iovec_len = FBR_BODY_SLAB_DEFAULT_CHUNKS;
	} else {
		fio->iovec_len *= 2;
	}

	if (fio->iovec == fio->_iovec) {
		fio->iovec = malloc(sizeof(*fio->iovec) * fio->iovec_len);
		assert(fio->iovec);

		memcpy(fio->iovec, fio->_iovec, sizeof(fio->_iovec));
	} else {
		fio->iovec = realloc(fio->iovec,
			sizeof(*fio->iovec) * fio->iovec_len);
		assert(fio->iovec);
	}

	assert_dev(fio->iovec_pos < fio->iovec_len);
}

static struct iovec *
_fio_iovec_get(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);

	if (fio->iovec_pos == fio->iovec_len) {
		_fio_iovec_expand(fio);
	}
	assert_dev(fio->iovec_pos < fio->iovec_len);

	struct iovec *io = &fio->iovec[fio->iovec_pos];

	return io;
}

static void
_fio_iovec_zero(struct fbr_fio *fio, size_t length)
{
	fbr_fio_ok(fio);

	while (length) {
		size_t zero_length = length;
		if (zero_length > sizeof(_ZERO_FILL)) {
			zero_length = sizeof(_ZERO_FILL);
		}

		struct iovec *iov = _fio_iovec_get(fio);

		iov->iov_base = _ZERO_FILL;
		iov->iov_len = zero_length;

		fio->iovec_pos++;
		length -= zero_length;
	}
}

static struct fbr_chunk *
_fio_find_next_chunk(struct fbr_fio *fio, size_t offset)
{
	fbr_fio_ok(fio);

	struct fbr_chunk *closest = NULL;
	size_t closest_distance = 0;

	for (size_t i = 0; i < fio->chunks_pos; i++) {
		struct fbr_chunk *chunk = fio->chunks[i];
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
_fio_find_chunk(struct fbr_fio *fio, size_t offset)
{
	fbr_fio_ok(fio);

	for (size_t i = 0; i < fio->chunks_pos; i++) {
		struct fbr_chunk *chunk = fio->chunks[i];
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
fbr_fio_iovec_gen(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, size_t size)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	assert(fio->iovec_len);

	fio->iovec_pos = 0;

	size_t offset_end = offset + size;
	size_t offset_pos = offset;

	while (offset_pos < offset_end) {
		struct fbr_chunk *chunk = _fio_find_chunk(fio, offset_pos);

		if (!chunk) {
			// Fill with the zero page
			chunk = _fio_find_next_chunk(fio, offset_pos);

			size_t zero_fill_length = offset_end - offset_pos;

			if (chunk) {
				fbr_chunk_ok(chunk);
				assert(chunk->offset > offset_pos);
				zero_fill_length = chunk->offset - offset_pos;
			}

			_fio_iovec_zero(fio, zero_fill_length);

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
			assert_dev(chunk_offset < chunk->length);
		}

		size_t chunk_length = chunk->length - chunk_offset;
		if (chunk_length > offset_end - offset_pos) {
			chunk_length = offset_end - offset_pos;
		}

		struct fbr_chunk *chunk_next = _fio_find_next_chunk(fio, offset_pos);

		if (chunk_next) {
			fbr_chunk_ok(chunk_next);
			assert_dev(chunk_next->offset > offset_pos);

			if (chunk_length > chunk_next->offset - offset_pos) {
				chunk_length = chunk_next->offset - offset_pos;
			}
		}

		// Can we merge into the last iovec?
		if (chunk_offset && fio->iovec_pos) {
			struct iovec *io_last = &fio->iovec[fio->iovec_pos - 1];

			if (io_last->iov_base == chunk->data &&
			    io_last->iov_len == chunk_offset) {
				io_last->iov_len += chunk_length;
				assert_dev(io_last->iov_len <= chunk->length);

				offset_pos += chunk_length;

				continue;
			}
		}

		struct iovec *iov = _fio_iovec_get(fio);

		iov->iov_base = chunk->data + chunk_offset;
		iov->iov_len = chunk_length;

		fio->iovec_pos++;
		offset_pos += chunk_length;

		// TODO
		assert(fio->iovec_pos <= FUSE_IOCTL_MAX_IOV);
	}

	assert_dev(offset_pos == offset_end);

	if (fbr_assert_is_dev()) {
		/*
		for (size_t i = 0; i < fio->chunks_pos; i++) {
			struct fbr_chunk *chunk = fio->chunks[i];
			fbr_chunk_ok(chunk);
			printf("ZZZ chunks[%zu].data = %p\n", i, (void*)chunk->data);
			printf("ZZZ chunks[%zu].offset = %zu\n", i, chunk->offset);
			printf("ZZZ chunks[%zu].length = %zu\n", i, chunk->length);
		}
		*/
		size_t total_size = 0;
		for (size_t i = 0; i < fio->iovec_pos; i++) {
			struct iovec *iov = &fio->iovec[i];
			/*
			printf("ZZZ iovec[%zu].iov_base = %p\n", i, (void*)iov->iov_base);
			printf("ZZZ iovec[%zu].iov_len = %zu\n", i, iov->iov_len);
			*/
			total_size += iov->iov_len;
		}
		assert(total_size == size);
	}
}

void
fbr_fio_free(struct fbr_fs *fs, struct fbr_fio *fio)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);

	fbr_body_LOCK(&fio->file->body);

	_fio_release_chunks(fio, 0);

	fbr_body_UNLOCK(&fio->file->body);

	fbr_inode_release(fs, &fio->file);
	assert_zero_dev(fio->file);

	if (fio->chunks != fio->_chunks) {
		free(fio->chunks);
	}

	if (fio->iovec != fio->_iovec) {
		free(fio->iovec);
	}

	fbr_ZERO(fio);

	free(fio);
}
