/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/store/fbr_store.h"

void _wbuffers_renew_id(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer,
	int have_file_lock);

void
fbr_wbuffer_init(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);

	pt_assert(pthread_mutex_init(&fio->wbuffer_lock, NULL));
	pt_assert(pthread_mutex_init(&fio->wbuffer_update_lock, NULL));
	pt_assert(pthread_cond_init(&fio->wbuffer_update, NULL));

	fio->wbuffers = NULL;
}

static struct fbr_wbuffer *
_wbuffer_alloc(struct fbr_fs *fs, struct fbr_fio *fio)
{
	assert_dev(fs);
	assert_dev(fio);

	struct fbr_wbuffer *wbuffer = calloc(1, sizeof(*wbuffer));
	assert(wbuffer);

	wbuffer->magic = FBR_WBUFFER_MAGIC;
	wbuffer->state = FBR_WBUFFER_WRITING;
	wbuffer->id = fbr_id_gen();
	wbuffer->fio = fio;

	fbr_fs_stat_add(&fs->stats.wbuffers);

	return wbuffer;
}

static struct fbr_wbuffer *
_wbuffer_alloc_buffer(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, size_t size,
    size_t max)
{
	assert_dev(fs);
	assert_dev(fio);
	assert(size);

	size_t wsize;

	if (fs->config.debug_wbuffer_size) {
		wsize = fs->config.debug_wbuffer_size;
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

	struct fbr_wbuffer *wbuffer = _wbuffer_alloc(fs, fio);

	wbuffer->offset = offset;
	wbuffer->size = wsize;
	wbuffer->end = size;

	wbuffer->free_buffer = 1;
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

	// Hole detected, split the wbuffer
	if (wbuffer && offset > (wbuffer->offset + wbuffer->end)) {
		assert_dev(offset > wbuffer->offset);
		assert_dev(offset < wbuffer->offset + wbuffer->size);
		assert_dev(wbuffer->size > wbuffer->end);

		size_t wbuffer_offset = offset - wbuffer->offset;
		prev = wbuffer;

		wbuffer = _wbuffer_alloc(fs, fio);

		wbuffer->offset = offset;
		wbuffer->size = prev->size - wbuffer_offset;
		wbuffer->end = size;
		if (wbuffer->end > wbuffer->size) {
			wbuffer->end = wbuffer->size;
		}

		wbuffer->buffer = prev->buffer + wbuffer_offset;
		wbuffer->split = 1;
		assert_zero_dev(wbuffer->free_buffer);

		prev->size = wbuffer_offset;

		wbuffer->next = prev->next;
		prev->next = wbuffer;

		fbr_rlog(FBR_LOG_WBUFFER, "hole detected hole: %zu offset: %zu end: %zu size: %zu",
			prev->offset + prev->end, offset, wbuffer->end, wbuffer->size);
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

		wbuffer = _wbuffer_alloc_buffer(fs, fio, offset, size, max);
		assert_dev(wbuffer);

		if (prev) {
			prev->next = wbuffer;
		} else {
			*head = wbuffer;
		}

		wbuffer->next = current;

		fbr_rlog(FBR_LOG_WBUFFER, "alloc offset: %zu end: %zu size: %zu"
			" current->offset: %zd", wbuffer->offset, wbuffer->end, wbuffer->size,
			current ? (ssize_t)current->offset : -1);
	} else {
		// Successful leftover from previous flush
		if (wbuffer->state != FBR_WBUFFER_WRITING) {
			assert_dev(wbuffer->state == FBR_WBUFFER_DONE);
			assert_dev(wbuffer->chunk);

			wbuffer->state = FBR_WBUFFER_WRITING;

			fbr_rlog(FBR_LOG_WBUFFER, "rewriting offset: %zu", wbuffer->offset);

			if (fs->store->chunk_delete_f) {
				fs->store->chunk_delete_f(fs, fio->file, wbuffer->chunk);
			}

			_wbuffers_renew_id(fs, fio->file, wbuffer, 1);
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
	fbr_fuse_LOCK(fs->fuse_ctx, &fio->wbuffer_lock);
}

static void
_wbuffer_UNLOCK(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);
	pt_assert(pthread_mutex_unlock(&fio->wbuffer_lock));
}

// Note: file->lock required
static void
_wbuffer_chunk_add(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer,
    int ready)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert_zero(wbuffer->chunk);
	assert_dev(fbr_file_has_wbuffer(file));

	fbr_rlog(FBR_LOG_WBUFFER, "new chunk offset: %zu length: %zu", wbuffer->offset,
		wbuffer->end);

	struct fbr_chunk *chunk = fbr_body_chunk_add(fs, file, wbuffer->id, wbuffer->offset,
		wbuffer->end);
	assert_dev(chunk);
	assert_dev(chunk->state == FBR_CHUNK_EMPTY);

	if (ready) {
		return;
	}

	chunk->state = FBR_CHUNK_WBUFFER;
	chunk->data = wbuffer->buffer;
	chunk->do_free = wbuffer->free_buffer;

	fbr_chunk_take(chunk);

	wbuffer->chunk = chunk;
	wbuffer->free_buffer = 0;
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
_wbuffers_renew_id(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer,
    int have_file_lock)
{
	assert_dev(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_WRITING);

	if (!have_file_lock) {
		fbr_file_LOCK(fs, file);
	}

	wbuffer->id = fbr_id_gen();

	if (wbuffer->chunk) {
		fbr_chunk_ok(wbuffer->chunk);
		wbuffer->chunk->id = wbuffer->id;
	}

	if (!have_file_lock) {
		fbr_file_UNLOCK(file);
	}
}

void
fbr_wbuffer_write(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, const char *buf,
    size_t size)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);
	assert(fio->write);
	assert_zero_dev(fio->read_only);
	assert(buf);
	assert(size);

	_wbuffer_LOCK(fs, fio);

	struct fbr_wbuffer *wbuffer = _wbuffer_get(fs, fio, offset, size);

	size_t offset_end = offset + size;
	size_t written = 0;

	fbr_file_LOCK(fs, fio->file);

	while (written < size) {
		fbr_wbuffer_ok(wbuffer);
		assert(wbuffer->state == FBR_WBUFFER_WRITING);

		size_t wbuffer_end = wbuffer->offset + wbuffer->size;
		assert(offset >= wbuffer->offset);
		assert(offset < wbuffer_end);

		size_t wbuffer_offset = offset - wbuffer->offset;
		assert_dev(wbuffer_offset <= wbuffer->end);

		size_t wsize = size - written;
		if (wsize > wbuffer->size - wbuffer_offset) {
			wsize = wbuffer->size - wbuffer_offset;
		}

		memcpy(wbuffer->buffer + wbuffer_offset, buf + written, wsize);

		if (wbuffer->end < wbuffer_offset + wsize) {
			fbr_rlog(FBR_LOG_WBUFFER, "extending offset: %zu end: %zu (was: %zu)",
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

		if (!wbuffer->chunk && !fio->append) {
			assert_zero_dev(wbuffer_offset);
			_wbuffer_chunk_add(fs, fio->file, wbuffer, 0);
		}

		offset = wbuffer_end;
		written += wsize;

		wbuffer = wbuffer->next;
	}


	if (fio->file->size < offset_end && !fio->append) {
		fbr_rlog(FBR_LOG_WBUFFER, "new file->size: %zu (was: %zu)", offset_end,
			fio->file->size);
		fio->file->size = offset_end;
	}

	assert_dev(written == size);

	fbr_file_UNLOCK(fio->file);
	_wbuffer_UNLOCK(fio);
}

void
fbr_wbuffer_update(struct fbr_fs *fs, struct fbr_wbuffer *wbuffer, enum fbr_wbuffer_state state)
{
	fbr_fs_ok(fs);
	fbr_wbuffer_ok(wbuffer);
	fbr_fio_ok(wbuffer->fio);
	assert(wbuffer->state == FBR_WBUFFER_SYNC);
	assert(state >= FBR_WBUFFER_DONE);

	fbr_fuse_LOCK(fs->fuse_ctx, &wbuffer->fio->wbuffer_update_lock);

	wbuffer->state = state;

	pt_assert(pthread_cond_broadcast(&wbuffer->fio->wbuffer_update));

	pt_assert(pthread_mutex_unlock(&wbuffer->fio->wbuffer_update_lock));
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

static void
_wbuffer_delete_chunk(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	assert_dev(fs);
	assert_dev(fs->store);
	assert_dev(file);
	fbr_wbuffer_ok(wbuffer);

	if (fs->store->chunk_delete_f) {
		struct fbr_chunk chunk;
		fbr_zero(&chunk);
		chunk.magic = FBR_CHUNK_MAGIC;
		chunk.id = wbuffer->id;
		chunk.offset = wbuffer->offset;

		fs->store->chunk_delete_f(fs, file, &chunk);

		fbr_zero(&chunk);
	}
}

void
fbr_wbuffers_error_reset(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffers,
    int revert_write, int have_file_lock)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(wbuffers);

	struct fbr_wbuffer *wbuffer = wbuffers;
	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		assert_dev(wbuffer->state >= FBR_WBUFFER_READY);
		assert_dev(wbuffer->state != FBR_WBUFFER_SYNC);

		if (wbuffer->state == FBR_WBUFFER_ERROR ||
			wbuffer->state == FBR_WBUFFER_READY) {
			wbuffer->state = FBR_WBUFFER_WRITING;
			_wbuffers_renew_id(fs, file, wbuffer, have_file_lock);
		}

		if (revert_write && wbuffer->state == FBR_WBUFFER_DONE) {
			wbuffer->state = FBR_WBUFFER_WRITING;
			_wbuffer_delete_chunk(fs, file, wbuffer);
			_wbuffers_renew_id(fs, file, wbuffer, have_file_lock);
		}

		wbuffer = wbuffer->next;
	}
}

int
fbr_wbuffer_flush_store(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffers,
    int revert_on_error, int have_file_lock)
{
	int error = 0;

	fbr_wbuffer_ok(wbuffers);
	struct fbr_fio *fio = wbuffers->fio;
	fbr_fio_ok(fio);

	fbr_fuse_LOCK(fs->fuse_ctx, &fio->wbuffer_update_lock);

	struct fbr_wbuffer *wbuffer = wbuffers;
	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		assert(wbuffer->end);

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

	// TODO we can check for ready later in the write pipeline
	// see: fbr_cstore_index_root_write()

	while (!_wbuffer_ready(wbuffers)) {
		if (_wbuffer_ready_error(wbuffers)) {
			fbr_rlog(FBR_LOG_ERROR, "wbuffer error state found, setting EIO");
			if (!error) {
				error = EIO;
			}
			break;
		}

		pt_assert(pthread_cond_wait(&fio->wbuffer_update, &fio->wbuffer_update_lock));
	}

	pt_assert(pthread_mutex_unlock(&fio->wbuffer_update_lock));

	if (error) {
		fbr_fs_stat_add(&fs->stats.flush_errors);
		fbr_wbuffers_error_reset(fs, file, wbuffers, revert_on_error, have_file_lock);
	}

	return error;
}

int
fbr_wbuffer_flush_fio(struct fbr_fs *fs, struct fbr_fio *fio)
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
	assert(fio->write);
	assert_zero_dev(fio->read_only);
	assert_dev(fbr_file_has_wbuffer(fio->file));

	struct fbr_file *file = fio->file;
	enum fbr_flush_flags flags = FBR_FLUSH_NONE;

	if (fio->append) {
		flags |= FBR_FLUSH_APPEND;
		flags |= FBR_FLUSH_DELAY_WRITE;
		fbr_fs_stat_add(&fs->stats.appends);
	}
	if (fio->truncate) {
		flags |= FBR_FLUSH_TRUNCATE;
	}

	int error = 0;
	if (!fbr_fs_is_flag(flags, FBR_FLUSH_DELAY_WRITE)) {
		error = fbr_wbuffer_flush_store(fs, file, fio->wbuffers, 0, 0);
	}

	if (error) {
		_wbuffer_UNLOCK(fio);
		return error;
	}

	if (fs->store->optional.directory_flush_f) {
		error = fs->store->optional.directory_flush_f(fs, file, fio->wbuffers, flags);
	} else {
		error = fbr_directory_flush(fs, file, fio->wbuffers, flags);
	}

	if (!error) {
		fbr_wbuffers_reset(fs, fio);
		fio->truncate = 0;
	} else {
		fbr_fs_stat_add(&fs->stats.flush_errors);
	}

	_wbuffer_UNLOCK(fio);

	return error;
}

// Note: file->lock required
void
fbr_wbuffers_ready(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffers,
    int chunk_add)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(wbuffers);

	struct fbr_wbuffer *wbuffer = wbuffers;
	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		assert(wbuffer->state == FBR_WBUFFER_DONE);

		if (chunk_add) {
			_wbuffer_chunk_add(fs, file, wbuffer, 1);

			wbuffer = wbuffer->next;
			continue;
		}

		struct fbr_chunk *chunk = wbuffer->chunk;
		fbr_chunk_ok(chunk);
		assert_dev(chunk->state == FBR_CHUNK_WBUFFER);
		assert_dev(chunk->data);

		fbr_rlog(FBR_LOG_DEBUG, "wbuffer chunk state: %s offset: %zu length: %zu",
			fbr_chunk_state_string(chunk->state), chunk->offset, chunk->length);

		chunk->state = FBR_CHUNK_READY;

		fbr_chunk_release(chunk);

		wbuffer->chunk = NULL;
		wbuffer->buffer = NULL;
		wbuffer->free_buffer = 0;

		wbuffer = wbuffer->next;
	}

	fbr_body_debug(fs, file);
}

void
fbr_wbuffers_reset(struct fbr_fs *fs, struct fbr_fio *fio)
{
	fbr_fio_ok(fio);

	fbr_file_LOCK(fs, fio->file);

	struct fbr_wbuffer *wbuffer = fio->wbuffers;
	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		assert(wbuffer->state != FBR_WBUFFER_SYNC);

		struct fbr_wbuffer *next = wbuffer->next;

		if (wbuffer->free_buffer) {
			assert_dev(wbuffer->buffer);
			assert_zero_dev(wbuffer->chunk);
			assert_zero_dev(wbuffer->split);
			free(wbuffer->buffer);
		} else if (wbuffer->chunk) {
			fbr_chunk_release(wbuffer->chunk);
		}

		fbr_zero(wbuffer);
		free(wbuffer);

		wbuffer = next;
	}

	fio->wbuffers = NULL;

	fbr_file_UNLOCK(fio->file);
}

void
fbr_wbuffers_reset_lock(struct fbr_fs *fs, struct fbr_fio *fio)
{
	fbr_fio_ok(fio);

	_wbuffer_LOCK(fs, fio);
	fbr_wbuffers_reset(fs, fio);
	_wbuffer_UNLOCK(fio);
}

void
fbr_wbuffer_free(struct fbr_fs *fs, struct fbr_fio *fio)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	fbr_file_ok(fio->file);

	pt_assert(pthread_mutex_destroy(&fio->wbuffer_lock));
	pt_assert(pthread_mutex_destroy(&fio->wbuffer_update_lock));
	pt_assert(pthread_cond_destroy(&fio->wbuffer_update));

	if (fio->wbuffers) {
		fbr_rlog(FBR_LOG_WBUFFER, "WARNING unflushed wbuffers exist");
	}
	// TODO get rid of this
	assert_zero_dev(fio->wbuffers);

	fbr_wbuffers_reset(fs, fio);
}
