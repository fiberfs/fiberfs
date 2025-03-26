/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/store/fbr_store.h"

void
fbr_wbuffer_init(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);

	pt_assert(pthread_mutex_init(&fio->wlock, NULL));
	fio->id = fbr_id_gen();
	fio->wbuffers = NULL;
}

static struct fbr_wbuffer *
_wbuffer_alloc(struct fbr_fio *fio, size_t offset, size_t size)
{
	assert_dev(fio);
	assert(size);

	size_t wsize = fbr_fs_chunk_size(offset);
	while (wsize < size) {
		wsize *= 2;
	}

	struct fbr_wbuffer *wbuffer = malloc(sizeof(*wbuffer) + wsize);
	assert(wbuffer);

	fbr_ZERO(wbuffer);
	wbuffer->magic = FBR_WBUFFER_MAGIC;
	wbuffer->state = FBR_WBUFFER_WRITING;
	wbuffer->id = fio->id;
	wbuffer->buffer = (uint8_t*)wbuffer + sizeof(*wbuffer);
	wbuffer->offset = offset;
	wbuffer->size = wsize;
	wbuffer->end = size;

	return wbuffer;
}

static struct fbr_wbuffer *
_wbuffer_find(struct fbr_fio *fio, struct fbr_wbuffer *head, size_t offset, size_t size)
{
	assert_dev(fio);

	struct fbr_wbuffer *wbuffer = NULL;
	struct fbr_wbuffer *prev = NULL;
	struct fbr_wbuffer *current = head;

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
			wbuffer->next = current;
		}
	} else {
		assert_dev(offset >= wbuffer->offset);
		size_t wbuffer_offset = offset - wbuffer->offset;
		size_t wbuffer_end = wbuffer_offset + size;

		if (wbuffer_end > wbuffer->size) {
			wbuffer_end = wbuffer->size;
		}
		if (wbuffer->end < wbuffer_end) {
			wbuffer->end = wbuffer_end;
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

	struct fbr_wbuffer *wbuffer = _wbuffer_find(fio, fio->wbuffers, offset, size);
	fbr_wbuffer_ok(wbuffer);

	if (!fio->wbuffers) {
		fio->wbuffers = wbuffer;
	}

	struct fbr_wbuffer *current = wbuffer;
	size_t current_end = current->offset + current->size;

	while (offset_end > current_end) {
		size_t diff = current_end - offset;
		assert_dev(diff < size);

		size -= diff;
		offset = current_end;

		struct fbr_wbuffer *next = _wbuffer_find(fio, current->next, offset, size);
		fbr_wbuffer_ok(next);

		if (!current->next) {
			current->next = next;
		}

		current = next;
		current_end = current->offset + current->size;
	}

	if (fbr_assert_is_dev()) {
		fbr_wbuffer_ok(fio->wbuffers);
		size_t i = 0;
		current = fio->wbuffers;
		while (current) {
			fbr_wbuffer_ok(current);
			///*
			fs->log("WWW wbuffer[%zu] offset: %zu end: %zu size: %zu", i,
				current->offset, current->end, current->size);
			//*/
			i++;
			current = current->next;
		}
	}

	return wbuffer;
}

void
fbr_wbuffer_LOCK(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);

	if (fio->read_only) {
		return;
	}

	pt_assert(pthread_mutex_lock(&fio->wlock));
}

void
fbr_wbuffer_UNLOCK(struct fbr_fio *fio)
{
	fbr_fio_ok(fio);

	if (fio->read_only) {
		return;
	}

	pt_assert(pthread_mutex_unlock(&fio->wlock));
}

size_t
fbr_wbuffer_write(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, const char *buf,
    size_t size)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	assert_zero_dev(fio->read_only);
	assert(buf);
	assert(size);

	fbr_wbuffer_LOCK(fio);

	struct fbr_wbuffer *wbuffer = _wbuffer_get(fs, fio, offset, size);

	size_t written = 0;

	while (written < size) {
		fbr_wbuffer_ok(wbuffer);

		size_t wbuffer_end = wbuffer->offset + wbuffer->size;
		assert(offset >= wbuffer->offset);
		assert(offset < wbuffer_end);

		size_t wbuffer_offset = offset - wbuffer->offset;

		size_t wsize = size - written;
		if (wsize > wbuffer->size - wbuffer_offset) {
			wsize = wbuffer->size - wbuffer_offset;
		}

		assert_dev(wbuffer_offset + wsize <= wbuffer->end);

		memcpy(wbuffer->buffer + wbuffer_offset, buf + written, wsize);

		offset = wbuffer_end;
		written += wsize;

		wbuffer = wbuffer->next;
	}

	assert_dev(written == size);

	fbr_wbuffer_UNLOCK(fio);

	return written;
}

static void
_wbuffer_free(struct fbr_wbuffer *wbuffer)
{
	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);

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

	fbr_wbuffer_LOCK(fio);

	if (!fio->wbuffers) {
		fbr_wbuffer_UNLOCK(fio);
		return 0;
	}

	fbr_wbuffer_ok(fio->wbuffers);
	assert_zero_dev(fio->read_only);

	struct fbr_wbuffer *wbuffers = fio->wbuffers;
	fio->wbuffers = 0;
	int ret = 0;

	if (fs->store->flush_wbuffer_f) {
		ret = fs->store->flush_wbuffer_f(fs, fio->file, wbuffers);
	} else {
		ret = EIO;
	}

	_wbuffer_free(wbuffers);

	fbr_wbuffer_UNLOCK(fio);

	return ret;
}

void
fbr_wbuffer_free(struct fbr_fs *fs, struct fbr_fio *fio)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);

	pt_assert(pthread_mutex_destroy(&fio->wlock));
	_wbuffer_free(fio->wbuffers);
}
