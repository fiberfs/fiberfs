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
	pt_assert(pthread_cond_init(&fio->wbuffer_update, NULL));

	fio->wbuffers = NULL;
}

static struct fbr_wbuffer *
_wbuffer_alloc(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, size_t size, size_t max)
{
	assert_dev(fs);
	assert_dev(fio);
	assert(size);

	size_t wsize;

	if (_DEBUG_WBUFFER_ALLOC_SIZE) {
		wsize = _DEBUG_WBUFFER_ALLOC_SIZE;
	} else {
		wsize = fbr_fs_chunk_size(offset);
	}

	while (wsize < size) {
		wsize *= 2;
	}

	if (max && wsize > max) {
		wsize = max;
	}
	assert_dev(size <= wsize);

	struct fbr_wbuffer *wbuffer = calloc(1, sizeof(*wbuffer));
	assert(wbuffer);

	wbuffer->magic = FBR_WBUFFER_MAGIC;
	wbuffer->state = FBR_WBUFFER_WRITING;
	wbuffer->id = fbr_id_gen();
	wbuffer->offset = offset;
	wbuffer->size = wsize;
	wbuffer->end = size;
	wbuffer->fio = fio;

	wbuffer->buffer = malloc(wsize);
	assert(wbuffer->buffer);

	fbr_fs_stat_add(&fs->stats.wbuffers);

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
		size_t max = 0;

		if (current) {
			assert_dev(current->offset > offset);
			max = current->offset - offset;
			if (size > max) {
				size = max;
			}
		}

		wbuffer = _wbuffer_alloc(fs, fio, offset, size, max);
		assert_dev(wbuffer);

		if (prev) {
			prev->next = wbuffer;
		} else {
			*head = wbuffer;
		}

		wbuffer->next = current;

		fs->log("WBUFFER alloc offset: %zu end: %zu size: %zu current->offset: %zd",
			wbuffer->offset, wbuffer->end, wbuffer->size,
			current ? (ssize_t)current->offset : -1);
	} else {
		// Successful leftover from previous flush
		if (wbuffer->state != FBR_WBUFFER_WRITING) {
			assert_dev(wbuffer->state == FBR_WBUFFER_DONE);
			assert_dev(wbuffer->chunk);

			wbuffer->state = FBR_WBUFFER_WRITING;

			if (fs->store->chunk_delete_f) {
				fs->store->chunk_delete_f(fs, fio->file, wbuffer->chunk);
			}
		}
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
		assert_dev(current->next == next);

		current = next;
		current_end = current->offset + current->size;
	}

	fbr_wbuffer_ok(fio->wbuffers);
	fbr_wbuffer_ok(wbuffer);

	return wbuffer;
}

static void
_wbuffer_LOCK(struct fbr_fs *fs, struct fbr_fio *fio)
{
	assert_dev(fs);
	fbr_fio_ok(fio);
	fbr_fuse_lock(fs->fuse_ctx, &fio->wbuffer_lock);
}

static void
_wbuffer_UNLOCK(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);
	pt_assert(pthread_mutex_unlock(&fio->wbuffer_lock));
}

void
fbr_wbuffer_write(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, const char *buf,
    size_t size)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);
	assert_zero_dev(fio->read_only);
	assert(buf);
	assert(size);

	_wbuffer_LOCK(fs, fio);

	struct fbr_wbuffer *wbuffer = _wbuffer_get(fs, fio, offset, size);

	size_t offset_end = offset + size;
	size_t written = 0;

	fbr_body_LOCK(fs, &fio->file->body);

	while (written < size) {
		fbr_wbuffer_ok(wbuffer);
		assert(wbuffer->state == FBR_WBUFFER_WRITING);

		size_t wbuffer_end = wbuffer->offset + wbuffer->size;
		assert(offset >= wbuffer->offset);
		assert(offset < wbuffer_end);

		size_t wbuffer_offset = offset - wbuffer->offset;

		if (wbuffer_offset > wbuffer->end) {
			size_t wbuffer_zero = wbuffer_offset - wbuffer->end;
			memset(wbuffer->buffer + wbuffer->end, 0, wbuffer_zero);
		}

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

			struct fbr_chunk *chunk = fbr_body_chunk_add(fs, fio->file, wbuffer->id,
				wbuffer->offset, wbuffer->end);
			assert_dev(chunk);
			assert_dev(chunk->state == FBR_CHUNK_EMPTY);

			chunk->state = FBR_CHUNK_WBUFFER;
			chunk->data = wbuffer->buffer;
			chunk->do_free = 1;

			fbr_chunk_take(chunk);

			wbuffer->chunk = chunk;
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
}

static void
_wbuffer_flush_chunks(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert_dev(wbuffer);

	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		assert(wbuffer->state == FBR_WBUFFER_DONE);

		struct fbr_chunk *chunk = wbuffer->chunk;
		fbr_chunk_ok(chunk);
		assert_dev(chunk->state == FBR_CHUNK_WBUFFER);
		assert_dev(chunk->data);

		fs->log("WBUFFER chunk state: %s offset: %zu length: %zu",
			fbr_chunk_state(chunk->state), chunk->offset, chunk->length);

		chunk->state = FBR_CHUNK_READY;

		fbr_chunk_release(chunk);

		wbuffer->chunk = NULL;
		wbuffer->buffer = NULL;

		wbuffer = wbuffer->next;
	}

	fbr_body_debug(fs, file);
}

void
fbr_wbuffer_update(struct fbr_fs *fs, struct fbr_wbuffer *wbuffer, enum fbr_wbuffer_state state)
{
	fbr_fs_ok(fs);
	fbr_wbuffer_ok(wbuffer);
	fbr_fio_ok(wbuffer->fio);
	assert(wbuffer->state == FBR_WBUFFER_SYNC);
	assert(state >= FBR_WBUFFER_DONE);

	_wbuffer_LOCK(fs, wbuffer->fio);

	wbuffer->state = state;

	pt_assert(pthread_cond_broadcast(&wbuffer->fio->wbuffer_update));

	_wbuffer_UNLOCK(wbuffer->fio);
}

static int
_wbuffer_ready_error(struct fbr_wbuffer *wbuffer)
{
	assert_dev(wbuffer);

	int error = 0;

	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		assert_dev(wbuffer->state);

		switch (wbuffer->state) {
			case FBR_WBUFFER_SYNC:
				return 0;
			case FBR_WBUFFER_DONE:
				break;
			default:
				error = 1;
				break;
		}

		wbuffer = wbuffer->next;
	}

	return error;
}

static int
_wbuffer_ready(struct fbr_wbuffer *wbuffer)
{
	assert_dev(wbuffer);

	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		assert_dev(wbuffer->state);

		if (wbuffer->state != FBR_WBUFFER_DONE) {
			return 0;
		}

		wbuffer = wbuffer->next;
	}

	return 1;
}

void
fbr_wbuffers_free(struct fbr_wbuffer *wbuffer)
{
	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		assert(wbuffer->state != FBR_WBUFFER_SYNC);

		struct fbr_wbuffer *next = wbuffer->next;

		if (wbuffer->buffer && !wbuffer->chunk) {
			free(wbuffer->buffer);
		} else if (wbuffer->chunk) {
			fbr_chunk_release(wbuffer->chunk);
		}

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

	_wbuffer_LOCK(fs, fio);

	if (!fio->wbuffers) {
		_wbuffer_UNLOCK(fio);
		return 0;
	}

	fbr_fs_stat_add(&fs->stats.flushes);

	fbr_wbuffer_ok(fio->wbuffers);
	assert_zero_dev(fio->read_only);

	struct fbr_file *file = fio->file;
	struct fbr_wbuffer *wbuffer = fio->wbuffers;
	int error = 0;

	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);

		if (wbuffer->state == FBR_WBUFFER_WRITING) {
			wbuffer->state = FBR_WBUFFER_READY;
			if (fs->store->wbuffer_write_f) {
				fs->store->wbuffer_write_f(fs, file, wbuffer);
			}
		} else {
			assert_dev(wbuffer->state == FBR_WBUFFER_DONE);
		}

		wbuffer = wbuffer->next;
	}

	while (!_wbuffer_ready(fio->wbuffers)) {
		if (_wbuffer_ready_error(fio->wbuffers)) {
			fs->log("WBUFFER error wbuffer found, setting error");
			if (!error) {
				error = EIO;
			}
			break;
		}

		pt_assert(pthread_cond_wait(&fio->wbuffer_update, &fio->wbuffer_lock));
	}

	if (error) {
		// Cleanup and keep the fio intact so we can potentially flush again and correct
		wbuffer = fio->wbuffers;

		while (wbuffer) {
			fbr_wbuffer_ok(wbuffer);
			assert_dev(wbuffer->state >= FBR_WBUFFER_DONE);

			if (wbuffer->state == FBR_WBUFFER_ERROR) {
				wbuffer->state = FBR_WBUFFER_WRITING;
			}

			wbuffer = wbuffer->next;
		}

		_wbuffer_UNLOCK(fio);

		return error;
	}

	// Note: we unlocked, potential changes:
	//  * file->size could change

	fbr_body_LOCK(fs, &file->body);

	enum fbr_index_flags flags = FBR_INDEX_NONE;
	if (fio->truncate) {
		flags |= FBR_INDEX_FILE_TRUNCATE;
	}

	if (fs->store->wbuffers_flush_f) {
		int ret = fs->store->wbuffers_flush_f(fs, file, fio->wbuffers, flags);
		if (ret && !error) {
			error = ret;
		}
	} else if (!error) {
		error = EIO;
	}

	if (!error) {
		_wbuffer_flush_chunks(fs, file, fio->wbuffers);

		fbr_wbuffers_free(fio->wbuffers);
		fio->wbuffers = NULL;
		fio->truncate = 0;
	}

	fbr_body_UNLOCK(&file->body);
	_wbuffer_UNLOCK(fio);

	return error;
}

int
fbr_wbuffer_has_chunk(struct fbr_wbuffer *wbuffer, struct fbr_chunk *chunk)
{
	fbr_chunk_ok(chunk);

	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);

		if (wbuffer->chunk == chunk) {
			return 1;
		}

		wbuffer = wbuffer->next;
	}

	return 0;
}

struct fbr_chunk_list *
fbr_wbuffer_chunks(struct fbr_wbuffer *wbuffer)
{
	struct fbr_chunk_list *chunks = fbr_chunk_list_alloc();

	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);

		chunks = fbr_chunk_list_add(chunks, wbuffer->chunk);

		wbuffer = wbuffer->next;
	}

	return chunks;
}

void
fbr_wbuffer_free(struct fbr_fs *fs, struct fbr_fio *fio)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);

	pt_assert(pthread_mutex_destroy(&fio->wbuffer_lock));
	pt_assert(pthread_cond_destroy(&fio->wbuffer_update));

	assert_zero_dev(fio->wbuffers);
	fbr_wbuffers_free(fio->wbuffers);
	fio->wbuffers = NULL;
}
