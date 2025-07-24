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
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/store/fbr_store.h"

static uint8_t _ZERO_FILL[1024 * 16];

struct fbr_fio *
fbr_fio_alloc(struct fbr_fs *fs, struct fbr_file *file, int read_only)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	struct fbr_fio *fio = calloc(1, sizeof(*fio));
	assert(fio);

	fio->magic = FBR_FIO_MAGIC;

	// Take an inode ref
	fbr_inode_add(fs, file);
	fio->file = file;

	fio->floating = fbr_chunk_list_alloc();
	fbr_chunk_list_ok(fio->floating);

	fbr_wbuffer_init(fio);

	// Caller owns a ref
	fio->refcount = 1;

	if (read_only) {
		fio->read_only = 1;
	} else {
		fio->write = 1;
		fbr_file_ref_wbuffer(fs, fio->file);
	}

	fbr_file_LOCK(fs, file);
	fbr_body_debug(fs, file);
	fbr_file_UNLOCK(file);

	return fio;
}

void
fbr_fio_take(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);
	assert(fio->refcount);

	fbr_refcount_t refs = fbr_atomic_add(&fio->refcount, 1);
	assert(refs > 1);
}

void
fbr_chunk_update(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk,
    enum fbr_chunk_state state)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_LOADING);

	switch (state) {
		case FBR_CHUNK_EMPTY:
		case FBR_CHUNK_LOADING:
		case FBR_CHUNK_READY:
		case FBR_CHUNK_SPLICED:
			break;
		default:
			fbr_ABORT("fbr_chunk_update() invalid state %d", state);
	}

	fbr_file_LOCK(fs, file);

	chunk->state = state;

	pt_assert(pthread_cond_broadcast(&file->update));

	fbr_file_UNLOCK(file);
}

static int
_fio_ready_error(struct fbr_chunk_list *chunks)
{
	assert_dev(chunks);

	int error = 0;

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);
		assert_dev(chunk->state);

		if (chunk->state == FBR_CHUNK_LOADING) {
			return 0;
		} else if (chunk->state == FBR_CHUNK_EMPTY) {
			error = 1;
		}
	}

	return error;
}

static int
_fio_ready(struct fbr_chunk_list *chunks)
{
	assert_dev(chunks);

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);
		assert_dev(chunk->state);

		if (chunk->state < FBR_CHUNK_READY) {
			return 0;
		}

		assert_dev(chunk->data);
	}

	return 1;
}

// Note: file->lock required
static struct fbr_chunk_list *
_fio_fetch_chunks(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, size_t size)
{
	fbr_fs_ok(fs);
	assert_dev(fs->store);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);
	assert(size);

	struct fbr_file *file = fio->file;
	struct fbr_chunk_list *chunks = fbr_body_chunk_range(file, offset, size, NULL, NULL);
	size_t offset_end = offset + size;

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);
		assert_dev(chunk->length);

		fbr_chunk_take(chunk);

		size_t chunk_end = chunk->offset + chunk->length;

		if (chunk->state == FBR_CHUNK_EMPTY) {
			// Single chunk is the offset, splicing is ok
			if (chunks->length == 1 &&
			    chunk->offset == offset &&
			    chunk_end == offset_end) {
				chunk->fd_splice_ok = 1;
			}

			assert_zero_dev(chunk->data);
			assert_zero_dev(chunk->chttp_splice);

			if (fs->store->chunk_read_f) {
				fs->store->chunk_read_f(fs, file, chunk);
			}
		}
	}

	while (!_fio_ready(chunks)) {
		if (_fio_ready_error(chunks)) {
			fbr_rlog(FBR_LOG_ERROR, "empty chunk found, setting error");
			fio->error = 1;
			break;
		}

		pt_assert(pthread_cond_wait(&file->update, &file->lock));
	}

	return chunks;
}

// Note: must have a file->lock
static void
_fio_release_floating(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset_end)
{
	assert_dev(fio);
	fbr_chunk_list_ok(fio->floating);

	// TODO we should track if the chunk was fully read and then release

	if (offset_end) {
		// Double the chunk size for offset_end and keep chunks in this range
		size_t floating_end = offset_end;
		if (floating_end <= 1024 * 256) {
			floating_end = 1024 * 256 + 1;
		}

		size_t chunk_size = fbr_fs_chunk_size(floating_end) * 2;

		if (offset_end > chunk_size) {
			offset_end -= chunk_size;
		} else {
			offset_end = 1;
		}

		assert_dev(fs);
		fbr_rlog(FBR_LOG_FIO, "floating offset_end: %zu", offset_end);
	}

	struct fbr_chunk_list *chunks = fio->floating;
	size_t keep = 0;

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);
		assert_dev(chunk->state == FBR_CHUNK_READY);

		size_t chunk_end = chunk->offset + chunk->length;

		if (offset_end && chunk_end >= offset_end) {
			chunks->list[keep] = chunk;
			keep++;
		} else {
			fbr_chunk_release(chunk);
		}
	}

	chunks->length = keep;
}

static struct fuse_bufvec *
_fio_bufvec_expand(struct fuse_bufvec *bufvec)
{
	if (!bufvec) {
		bufvec = malloc(sizeof(*bufvec) +
			(sizeof(*bufvec->buf) * FBR_BODY_DEFAULT_CHUNKS));
		assert(bufvec);

		bufvec->count = 1 + FBR_BODY_DEFAULT_CHUNKS;
		bufvec->idx = 0;
		bufvec->off = 0;
	} else {
		assert(bufvec->count);
		assert(bufvec->count < FUSE_IOCTL_MAX_IOV);

		bufvec->count *= 2;

		bufvec = realloc(bufvec, sizeof(*bufvec) +
			(sizeof(*bufvec->buf) * bufvec->count));
		assert(bufvec);

		bufvec->count++;
	}

	return bufvec;
}

static struct fuse_bufvec *
_fio_bufvec_zero(struct fuse_bufvec *bufvec, size_t length)
{
	assert(bufvec);

	while (length) {
		size_t zero_length = length;
		if (zero_length > sizeof(_ZERO_FILL)) {
			zero_length = sizeof(_ZERO_FILL);
		}

		if (bufvec->idx == bufvec->count) {
			bufvec = _fio_bufvec_expand(bufvec);
		}
		assert_dev(bufvec->idx < bufvec->count);

		struct fuse_buf *buf = &bufvec->buf[bufvec->idx];
		bufvec->idx++;

		fbr_ZERO(buf);

		buf->mem = _ZERO_FILL;
		buf->size = zero_length;

		length -= zero_length;
	}

	return bufvec;
}

struct fbr_chunk_vector *
fbr_fio_vector_gen(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, size_t size)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);

	fbr_file_LOCK(fs, fio->file);

	fio->error = 0;

	size_t file_size = fio->file->size;

	if (offset >= file_size) {
		fbr_file_UNLOCK(fio->file);
		return NULL;
	}
	if (offset + size > file_size) {
		size = file_size - offset;
	}
	if (!size) {
		fbr_file_UNLOCK(fio->file);
		return NULL;
	}

	struct fbr_chunk_list *chunks = _fio_fetch_chunks(fs, fio, offset, size);
	fbr_chunk_list_ok(chunks);

	// Note: file could be unlocked in _fio_fetch_chunks(), potential changes:
	//  * chunk->length can increase
	//  * file->size can change

	struct fbr_chunk_vector *vector = malloc(sizeof(*vector));
	assert(vector);

	vector->magic = FBR_CHUNK_VECTOR_MAGIC;
	vector->chunks = chunks;
	vector->bufvec = NULL;
	vector->offset = offset;
	vector->size = size;

	if (fio->error) {
		fbr_file_UNLOCK(fio->file);
		fbr_fio_vector_free(fs, fio, vector);
		return NULL;
	}

	struct fuse_bufvec *bufvec = _fio_bufvec_expand(NULL);

	size_t offset_end = offset + size;
	size_t offset_pos = offset;

	while (offset_pos < offset_end) {
		struct fbr_chunk *chunk = fbr_chunk_list_find(chunks, offset_pos);

		if (!chunk) {
			// Fill with the zero page
			chunk = fbr_chunk_list_next(chunks, offset_pos);

			size_t zero_fill_length = offset_end - offset_pos;

			if (chunk) {
				fbr_chunk_ok(chunk);
				assert(chunk->offset > offset_pos);
				zero_fill_length = chunk->offset - offset_pos;
			}

			bufvec = _fio_bufvec_zero(bufvec, zero_fill_length);

			offset_pos += zero_fill_length;

			if (!chunk) {
				continue;
			}
		}

		fbr_chunk_ok(chunk);
		assert(chunk->state >= FBR_CHUNK_READY);

		size_t chunk_offset = 0;
		if (chunk->offset < offset_pos) {
			chunk_offset = offset_pos - chunk->offset;
			assert_dev(chunk_offset < chunk->length);
		}

		size_t chunk_length = chunk->length - chunk_offset;
		if (chunk_length > offset_end - offset_pos) {
			chunk_length = offset_end - offset_pos;
		}

		struct fbr_chunk *chunk_next = fbr_chunk_list_next(chunks, offset_pos);

		if (chunk_next) {
			fbr_chunk_ok(chunk_next);
			assert_dev(chunk_next->offset > offset_pos);

			if (chunk_length > chunk_next->offset - offset_pos) {
				chunk_length = chunk_next->offset - offset_pos;
			}
		}

		// Can we merge into the last iovec?
		if (chunk_offset && bufvec->idx) {
			struct fuse_buf *buf_last = &bufvec->buf[bufvec->idx - 1];

			if (buf_last->mem == chunk->data &&
			    buf_last->size == chunk_offset) {
				buf_last->size += chunk_length;
				assert_dev(buf_last->size <= chunk->length);

				offset_pos += chunk_length;

				continue;
			}
		}

		assert(chunk->state != FBR_CHUNK_SPLICED);
		assert(chunk->data);

		if (bufvec->idx == bufvec->count) {
			bufvec = _fio_bufvec_expand(bufvec);
		}
		assert_dev(bufvec->idx < bufvec->count);

		struct fuse_buf *buf = &bufvec->buf[bufvec->idx];
		bufvec->idx++;

		fbr_ZERO(buf);

		buf->mem = chunk->data + chunk_offset;
		buf->size = chunk_length;

		// Debugging
		buf->pos = (off_t)chunk_offset;
		assert_zero_dev(buf->flags & FUSE_BUF_FD_SEEK);

		offset_pos += chunk_length;
	}

	bufvec->count = bufvec->idx;
	bufvec->idx = 0;

	vector->bufvec = bufvec;

	fbr_file_UNLOCK(fio->file);

	assert_dev(offset_pos == offset_end);

	fbr_chunk_list_debug(fs, vector->chunks, "FIO");

	// TODO this is debug
	size_t total_size = 0;
	for (size_t i = 0; i < bufvec->count; i++) {
		struct fuse_buf *buf = &bufvec->buf[i];
		fbr_rlog(FBR_LOG_DEBUG, "vector bufvec[%zu] mem: %p offset: %zu size: %zu", i,
			(void*)((char*)buf->mem - buf->pos), buf->pos,
			buf->size);
		total_size += buf->size;
	}
	assert(total_size == size);

	fbr_chunk_vector_ok(vector);

	return vector;
}

void
fbr_fio_vector_free(struct fbr_fs *fs, struct fbr_fio *fio, struct fbr_chunk_vector *vector)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);
	fbr_chunk_vector_ok(vector);

	struct fbr_chunk_list *chunks = vector->chunks;
	fbr_chunk_list_ok(chunks);

	size_t offset = vector->offset;
	size_t size = vector->size;

	if (vector->bufvec) {
		fbr_ZERO(vector->bufvec);
		free(vector->bufvec);
	}

	fbr_ZERO(vector);
	free(vector);

	// Try to keep more chunks around incase of slow parallel reads
	size_t offset_end = offset + size;

	fbr_file_LOCK(fs, fio->file);

	if (fio->error) {
		_fio_release_floating(fs, fio, 0);
	} else {
		_fio_release_floating(fs, fio, offset_end);
	}

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);
		assert_dev(chunk->state != FBR_CHUNK_LOADING);

		chunks->list[i] = NULL;

		if (fbr_chunk_list_contains(fio->floating, chunk)) {
			fbr_chunk_release(chunk);
			continue;
		}

		size_t chunk_end = chunk->offset + chunk->length;

		// chunk ends after offset_end
		if (chunk_end > offset_end && chunk->state == FBR_CHUNK_READY) {
			assert(chunk->offset < offset_end);
			fio->floating = fbr_chunk_list_add(fio->floating, chunk);
		} else {
			fbr_chunk_release(chunk);
		}
	}

	fbr_chunk_list_free(chunks);

	fbr_chunk_list_ok(fio->floating);
	fbr_chunk_list_debug(fs, fio->floating, "FLOATING");

	fbr_file_UNLOCK(fio->file);
}

void
fbr_fio_release(struct fbr_fs *fs, struct fbr_fio *fio)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);
	assert(fio->refcount);

	fbr_refcount_t refs = fbr_atomic_sub(&fio->refcount, 1);

	if (refs) {
		return;
	}

	if (fio->floating->length) {
		fbr_file_LOCK(fs, fio->file);
		_fio_release_floating(fs, fio, 0);
		fbr_file_UNLOCK(fio->file);
		assert_zero_dev(fio->floating->length);
	}

	fbr_chunk_list_free(fio->floating);
	fbr_wbuffer_free(fs, fio);

	if (fio->write) {
		assert_zero_dev(fio->read_only);
		fbr_file_release_wbuffer(fs, fio->file);
	}

	fbr_inode_release(fs, &fio->file);
	assert_zero_dev(fio->file);

	fbr_ZERO(fio);
	free(fio);
}
