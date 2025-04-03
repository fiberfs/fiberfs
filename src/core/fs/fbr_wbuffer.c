/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/store/fbr_store.h"

int _DEBUG_WBUFFER_ALLOC_SIZE;

void
fbr_wbuffer_init(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);

	pt_assert(pthread_mutex_init(&fio->wbuffer_lock, NULL));
	fio->id = fbr_id_gen();
	fio->wbuffers = NULL;
}

static struct fbr_wbuffer *
_wbuffer_alloc(struct fbr_fio *fio, size_t offset, size_t size)
{
	assert_dev(fio);
	assert(size);

	size_t wsize = fbr_fs_chunk_size(offset);

	if (_DEBUG_WBUFFER_ALLOC_SIZE) {
		wsize = _DEBUG_WBUFFER_ALLOC_SIZE;
	}

	while (wsize < size) {
		wsize *= 2;
	}

	struct fbr_wbuffer *wbuffer = calloc(1, sizeof(*wbuffer));
	assert(wbuffer);

	wbuffer->magic = FBR_WBUFFER_MAGIC;
	wbuffer->state = FBR_WBUFFER_WRITING;
	wbuffer->id = fio->id;
	wbuffer->offset = offset;
	wbuffer->size = wsize;
	wbuffer->end = size;

	wbuffer->buffer = malloc(wsize);
	assert(wbuffer->buffer);

	return wbuffer;
}

static struct fbr_wbuffer *
_wbuffer_find(struct fbr_fs *fs, struct fbr_fio *fio, struct fbr_wbuffer **head,
    size_t offset, size_t size)
{
	assert_dev(fs);
	assert_dev(fio);
	assert_dev(head);

	struct fbr_wbuffer *wbuffer = NULL;
	struct fbr_wbuffer *prev = NULL;
	struct fbr_wbuffer *current = *head;

	while (current) {
		fbr_wbuffer_ok(current);

		size_t current_end = current->offset + current->size;

		if (offset < current->offset) {
			assert_zero_dev(wbuffer);
			break;
		} else if (offset >= current->offset && offset < current_end) {
			wbuffer = current;
			break;
		}

		prev = current;
		current = current->next;
	}

	if (!wbuffer) {
		wbuffer = _wbuffer_alloc(fio, offset, size);
		assert_dev(wbuffer);

		if (prev) {
			prev->next = wbuffer;
		} else {
			*head = wbuffer;
		}

		wbuffer->next = current;

		fs->log("WBUFFER alloc offset: %zu end: %zu size: %zu",
			wbuffer->offset, wbuffer->end, wbuffer->size);
	}

	return wbuffer;
}

static struct fbr_wbuffer *
_wbuffer_get(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, size_t size)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	assert(size);

	size_t offset_end = offset + size;

	struct fbr_wbuffer *wbuffer = _wbuffer_find(fs, fio, &fio->wbuffers, offset, size);
	fbr_wbuffer_ok(wbuffer);

	struct fbr_wbuffer *current = wbuffer;
	size_t current_end = current->offset + current->size;

	while (offset_end > current_end) {
		size_t diff = current_end - offset;
		assert_dev(diff < size);

		size -= diff;
		offset = current_end;

		struct fbr_wbuffer *next = _wbuffer_find(fs, fio, &current->next, offset, size);
		fbr_wbuffer_ok(next);

		current = next;
		current_end = current->offset + current->size;
	}

	fbr_wbuffer_ok(fio->wbuffers);
	fbr_wbuffer_ok(wbuffer);

	return wbuffer;
}

static void
_wbuffer_LOCK(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);
	pt_assert(pthread_mutex_lock(&fio->wbuffer_lock));
}

static void
_wbuffer_UNLOCK(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);
	pt_assert(pthread_mutex_unlock(&fio->wbuffer_lock));
}

size_t
fbr_wbuffer_write(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, const char *buf,
    size_t size)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);
	assert_zero_dev(fio->read_only);
	assert(buf);
	assert(size);

	_wbuffer_LOCK(fio);

	struct fbr_wbuffer *wbuffer = _wbuffer_get(fs, fio, offset, size);

	size_t offset_end = offset + size;
	size_t written = 0;

	fbr_body_LOCK(&fio->file->body);

	while (written < size) {
		fbr_wbuffer_ok(wbuffer);
		assert(wbuffer->state == FBR_WBUFFER_WRITING);

		size_t wbuffer_end = wbuffer->offset + wbuffer->size;
		assert(offset >= wbuffer->offset);
		assert(offset < wbuffer_end);

		size_t wbuffer_offset = offset - wbuffer->offset;

		size_t wsize = size - written;
		if (wsize > wbuffer->size - wbuffer_offset) {
			wsize = wbuffer->size - wbuffer_offset;
		}

		memcpy(wbuffer->buffer + wbuffer_offset, buf + written, wsize);

		if (wbuffer->end < wbuffer_offset + wsize) {
			fs->log("WBUFFER extending offset: %zu end: %zu (was: %zu)",
				wbuffer->offset, wbuffer_offset + wsize, wbuffer->end);

			wbuffer->end = wbuffer_offset + wsize;
			assert_dev(wbuffer->end <= wbuffer->size);

			// Extend the file chunk
			if (wbuffer->chunk) {
				fbr_chunk_ok(wbuffer->chunk);
				assert_dev(wbuffer->chunk->length < wbuffer->end);

				wbuffer->chunk->length = wbuffer->end;
			}
		}

		if (!wbuffer->chunk) {
			assert_zero_dev(wbuffer_offset);

			fs->log("WBUFFER new chunk offset: %zu length: %zu",
				wbuffer->offset, wbuffer->end);

			struct fbr_chunk *chunk = fbr_body_chunk_add(fio->file, wbuffer->id,
				wbuffer->offset, wbuffer->end);
			assert_dev(chunk);
			assert_dev(chunk->state == FBR_CHUNK_EMPTY);

			chunk->state = FBR_CHUNK_WBUFFER;
			chunk->data = wbuffer->buffer;
			chunk->do_free = 1;

			fbr_chunk_take(chunk);

			wbuffer->chunk = chunk;
		}

		if (wbuffer->end == wbuffer->size) {
			wbuffer->state = FBR_WBUFFER_READY;
			if (fs->store->store_wbuffer_f) {
				int error = fs->store->store_wbuffer_f(fs, fio->file, wbuffer);
				if (error) {
					wbuffer->state = FBR_WBUFFER_ERROR;
				}
			}
		}

		offset = wbuffer_end;
		written += wsize;

		wbuffer = wbuffer->next;
	}


	if (fio->file->size < offset_end) {
		fs->log("WBUFFER new file->size: %zu (was: %zu)",
			offset_end, fio->file->size);

		fio->file->size = offset_end;
	}

	assert_dev(written == size);

	fbr_body_UNLOCK(&fio->file->body);
	_wbuffer_UNLOCK(fio);

	return written;
}

static void
_wbuffer_flush_chunks(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert_dev(wbuffer);

	fbr_body_LOCK(&file->body);

	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		assert(wbuffer->state >= FBR_WBUFFER_DONE);

		struct fbr_chunk *chunk = wbuffer->chunk;
		fbr_chunk_ok(chunk);
		assert_dev(chunk->state == FBR_CHUNK_WBUFFER);

		fs->log("WBUFFER chunk state: %s offset: %zu length: %zu",
			fbr_chunk_state(chunk->state), chunk->offset, chunk->length);

		fbr_chunk_release(chunk);
		wbuffer->buffer = NULL;

		wbuffer = wbuffer->next;
	}

	fbr_body_debug(fs, file);

	fbr_body_UNLOCK(&file->body);
}

static void
_wbuffer_free(struct fbr_wbuffer *wbuffer)
{
	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		assert(wbuffer->state != FBR_WBUFFER_SYNC);
		assert_zero(wbuffer->buffer);

		struct fbr_wbuffer *next = wbuffer->next;

		fbr_ZERO(wbuffer);
		free(wbuffer);

		wbuffer = next;
	}
}

int
fbr_wbuffer_flush(struct fbr_fs *fs, struct fbr_fio *fio)
{
	fbr_fs_ok(fs);
	assert_dev(fs->store);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);

	_wbuffer_LOCK(fio);

	if (!fio->wbuffers) {
		_wbuffer_UNLOCK(fio);
		return 0;
	}

	fbr_wbuffer_ok(fio->wbuffers);
	assert_zero_dev(fio->read_only);

	struct fbr_wbuffer *wbuffer = fio->wbuffers;
	int error = 0;

	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);

		if (wbuffer->state == FBR_WBUFFER_WRITING) {
			wbuffer->state = FBR_WBUFFER_READY;
			if (fs->store->store_wbuffer_f) {
				int ret = fs->store->store_wbuffer_f(fs, fio->file, wbuffer);
				if (ret) {
					error = ret;
					wbuffer->state = FBR_WBUFFER_ERROR;
				}
			}
		}

		wbuffer = wbuffer->next;
	}

	// wait for all the wbuffers here

	if (fs->store->flush_wbuffers_f) {
		int ret = fs->store->flush_wbuffers_f(fs, fio->file, fio->wbuffers);
		if (ret && !error) {
			error = ret;
		}
	} else if (!error) {
		error = EIO;
	}

	_wbuffer_flush_chunks(fs, fio->file, fio->wbuffers);

	_wbuffer_free(fio->wbuffers);
	fio->wbuffers = NULL;

	_wbuffer_UNLOCK(fio);

	return error;
}

void
fbr_wbuffer_free(struct fbr_fs *fs, struct fbr_fio *fio)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);

	pt_assert(pthread_mutex_destroy(&fio->wbuffer_lock));

	assert_zero_dev(fio->wbuffers);
	_wbuffer_free(fio->wbuffers);
}
