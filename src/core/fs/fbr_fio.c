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

static struct fbr_chunk_list *
_fio_chunk_list_expand(struct fbr_chunk_list *chunks)
{
	if (!chunks) {
		chunks = malloc(sizeof(*chunks) +
			(sizeof(*chunks->list) * FBR_BODY_DEFAULT_CHUNKS));
		assert(chunks);

		chunks->magic = FBR_CHUNK_LIST_MAGIC;
		chunks->capacity = FBR_BODY_DEFAULT_CHUNKS;
		chunks->length = 0;
	} else {
		fbr_chunk_list_ok(chunks);
		assert(chunks->capacity);
		assert(chunks->capacity < FUSE_IOCTL_MAX_IOV);

		chunks->capacity *= 2;

		chunks = realloc(chunks, sizeof(*chunks) +
			(sizeof(*chunks->list) * chunks->capacity));
	}

	return chunks;
}

struct fbr_fio *
fbr_fio_alloc(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	struct fbr_fio *fio = calloc(1, sizeof(*fio));
	assert(fio);

	fio->magic = FBR_FIO_MAGIC;
	fio->file = file;

	fio->floating = _fio_chunk_list_expand(NULL);
	fbr_chunk_list_ok(fio->floating);

	return fio;
}

// TODO we dont need offset...
static void
_fio_release_floating(struct fbr_fio *fio, size_t offset)
{
	fbr_fio_ok(fio);
	fbr_chunk_list_ok(fio->floating);

	struct fbr_chunk_list *chunks = fio->floating;
	size_t keep = 0;

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);

		size_t chunk_end = chunk->offset + chunk->length;

		if (offset && chunk_end > offset) {
			chunks->list[keep] = chunk;
			keep++;
		} else {
			fbr_chunk_release(chunk);
		}
	}

	chunks->length = keep;
}

static struct fbr_chunk_list *
_fio_chunk_list_add(struct fbr_chunk_list *chunks, struct fbr_chunk *chunk)
{
	fbr_chunk_list_ok(chunks);
	fbr_chunk_ok(chunk);

	if (chunks->length == chunks->capacity) {
		chunks = _fio_chunk_list_expand(chunks);
	}
	assert_dev(chunks->length < chunks->capacity);

	chunks->list[chunks->length] = chunk;
	chunks->length++;

	return chunks;
}

static int
_fio_ready_error(struct fbr_chunk_list *chunks)
{
	fbr_chunk_list_ok(chunks);

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);

		if (chunk->state == FBR_CHUNK_EMPTY) {
			return 1;
		}
	}

	return 0;
}

static int
_fio_ready(struct fbr_chunk_list *chunks)
{
	fbr_chunk_list_ok(chunks);

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);

		if (chunk->state != FBR_CHUNK_READY) {
			return 0;
		}
	}

	return 1;
}

struct fbr_chunk_list *
fbr_fio_pull_chunks(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset,
    size_t size)
{
	fbr_fs_ok(fs);
	assert_dev(fs->store);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);

	fio->error = 0;

	struct fbr_body *body = &fio->file->body;
	size_t offset_end = offset + size;
	struct fbr_chunk_list *chunks = _fio_chunk_list_expand(NULL);

	fbr_body_LOCK(body);

	struct fbr_chunk *chunk = body->chunks;

	while (chunk) {
		fbr_chunk_ok(chunk);
		assert(chunk->state >= FBR_CHUNK_EMPTY);

		size_t chunk_end = chunk->offset + chunk->length;

		// offset starts in chunk || offset ends in chunk
		if ((offset >= chunk->offset && offset < chunk_end) ||
		    (offset < chunk->offset && offset_end >= chunk->offset)) {
			fbr_chunk_take(chunk);
			chunks = _fio_chunk_list_add(chunks, chunk);
		} else if (chunk->offset > offset_end) {
			break;
		}

		chunk = chunk->next;
	}

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);

		size_t chunk_end = chunk->offset + chunk->length;

		if (chunk->state == FBR_CHUNK_EMPTY) {
			// Single chunk fits in offset, splicing is ok
			if (chunks->length == 1 &&
			    chunk->offset >= offset &&
			    chunk_end <= offset_end) {
				chunk->fd_splice_ok = 1;
			}

			if (fs->store->fetch_chunk_f) {
				fs->store->fetch_chunk_f(fs, fio->file, chunk);
			}
		}
	}

	while (!_fio_ready(chunks)) {
		if (_fio_ready_error(chunks)) {
			fio->error = 1;
			break;
		}

		pthread_cond_wait(&body->update, &body->lock);
	}

	// TODO remove this
	_fio_release_floating(fio, 0);

	fbr_body_UNLOCK(body);

	return chunks;
}

// TODO better understand what happens concurrent reads happen
void
fbr_fio_release_chunks(struct fbr_fio *fio, struct fbr_chunk_list *chunks, size_t offset_end)
{
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);
	fbr_chunk_list_ok(fio->floating);
	fbr_chunk_list_ok(chunks);

	fbr_body_LOCK(&fio->file->body);

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);

		chunks->list[i] = NULL;

		size_t chunk_end = chunk->offset + chunk->length;

		// chunk starts before offset_end and ends after
		if (offset_end && chunk->offset < offset_end &&
		    chunk_end > offset_end) {
			assert_zero(chunk->fd_splice_ok);
			assert_zero_dev(chunk->fd_spliced);

			fio->floating = _fio_chunk_list_add(fio->floating, chunk);
		} else {
			fbr_chunk_release(chunk);
		}
	}

	fbr_ZERO(chunks);
	free(chunks);

	fbr_body_UNLOCK(&fio->file->body);
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

static struct fbr_chunk *
_fio_find_next_chunk(struct fbr_chunk_list *chunks, size_t offset)
{
	fbr_chunk_list_ok(chunks);

	struct fbr_chunk *closest = NULL;
	size_t closest_distance = 0;

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
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
_fio_find_chunk(struct fbr_chunk_list *chunks, size_t offset)
{
	fbr_chunk_list_ok(chunks);

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);

		size_t chunk_end = chunk->offset + chunk->length;

		// chunk covers offset
		if (chunk->offset <= offset && chunk_end > offset) {
			return chunk;
		}
	}

	return NULL;
}

struct fuse_bufvec *
fbr_fio_bufvec_gen(struct fbr_fs *fs, struct fbr_chunk_list *chunks, size_t offset, size_t size)
{
	fbr_fs_ok(fs);
	fbr_chunk_list_ok(chunks);

	struct fuse_bufvec *bufvec = _fio_bufvec_expand(NULL);

	size_t offset_end = offset + size;
	size_t offset_pos = offset;

	while (offset_pos < offset_end) {
		struct fbr_chunk *chunk = _fio_find_chunk(chunks, offset_pos);

		if (!chunk) {
			// Fill with the zero page
			chunk = _fio_find_next_chunk(chunks, offset_pos);

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

		struct fbr_chunk *chunk_next = _fio_find_next_chunk(chunks, offset_pos);

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

		if (bufvec->idx == bufvec->count) {
			bufvec = _fio_bufvec_expand(bufvec);
		}
		assert_dev(bufvec->idx < bufvec->count);

		struct fuse_buf *buf = &bufvec->buf[bufvec->idx];
		bufvec->idx++;

		fbr_ZERO(buf);

		buf->mem = chunk->data + chunk_offset;
		buf->size = chunk_length;

		offset_pos += chunk_length;
	}

	bufvec->count = bufvec->idx;
	bufvec->idx = 0;

	assert_dev(offset_pos == offset_end);

	if (fbr_assert_is_dev()) {
		assert(fs->log);
		///*
		for (size_t i = 0; i < chunks->length; i++) {
			struct fbr_chunk *chunk = chunks->list[i];
			fbr_chunk_ok(chunk);
			fs->log("ZZZ chunks[%zu] data: %p off: %zu len: %zu", i,
				(void*)chunk->data, chunk->offset, chunk->length);
		}
		//*/
		size_t total_size = 0;
		for (size_t i = 0; i < bufvec->count; i++) {
			struct fuse_buf *buf = &bufvec->buf[i];
			///*
			fs->log("ZZZ bufvec[%zu] mem: %p size: %zu", i, (void*)buf->mem,
				buf->size);
			//*/
			total_size += buf->size;
		}
		assert(total_size == size);
	}

	return bufvec;
}

void
fbr_fio_free(struct fbr_fs *fs, struct fbr_fio *fio)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);

	fbr_body_LOCK(&fio->file->body);
	_fio_release_floating(fio, 0);
	fbr_body_UNLOCK(&fio->file->body);

	assert_zero_dev(fio->floating->length);
	free(fio->floating);

	fbr_inode_release(fs, &fio->file);
	assert_zero_dev(fio->file);

	fbr_ZERO(fio);

	free(fio);
}
