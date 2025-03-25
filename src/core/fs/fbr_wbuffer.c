/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"

struct fbr_wbuffer *
_wbuffer_alloc(size_t offset, size_t size)
{
	size_t wsize = fbr_fs_chunk_size(offset);
	while (wsize < size) {
		wsize *= 2;
	}

	struct fbr_wbuffer *wbuffer = malloc(sizeof(*wbuffer) + wsize);
	assert(wbuffer);

	fbr_ZERO(wbuffer);
	wbuffer->magic = FBR_WBUFFER_MAGIC;
	wbuffer->buffer = (uint8_t*)wbuffer + sizeof(*wbuffer);
	wbuffer->offset = offset;
	wbuffer->size = wsize;
	wbuffer->end = size;

	return wbuffer;
}

struct fbr_wbuffer *
_wbuffer_get(struct fbr_wbuffer *head, size_t offset, size_t size)
{
	struct fbr_wbuffer *wbuffer = NULL;
	struct fbr_wbuffer *prev = NULL;
	struct fbr_wbuffer *current = head;

	while (current) {
		fbr_wbuffer_ok(current);

		size_t current_end = current->offset + current->size;

		if (offset < current->offset) {
			break;
		} else if (offset >= current->offset && offset < current_end) {
			wbuffer = current;
			break;
		}

		prev = current;
		current = current->next;
	}

	if (!wbuffer) {
		wbuffer = _wbuffer_alloc(offset, size);
		assert_dev(wbuffer);

		if (prev) {
			prev->next = wbuffer;
			wbuffer->next = current;
		}
	} else {
		assert_dev(offset >= wbuffer->offset);
		offset -= wbuffer->offset;
		wbuffer->end = offset + size;
		assert_dev(wbuffer->end <= wbuffer->size);
	}

	return wbuffer;
}

struct fbr_wbuffer *
fbr_wbuffer_get(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset, size_t size)
{
	fbr_fs_ok(fs);
	fbr_fio_ok(fio);
	assert(size);

	pt_assert(pthread_mutex_lock(&fio->wlock));

	size_t offset_end = offset + size;

	struct fbr_wbuffer *wbuffer = _wbuffer_get(fio->wbuffers, offset, size);
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

		struct fbr_wbuffer *next = _wbuffer_get(current->next, offset, size);
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
			fs->log("ZZZ wbuffer[%zu] offset: %zu end: %zu size: %zu", i,
				current->offset, current->end, current->size);
			//*/
			i++;
			current = current->next;
		}
	}

	pt_assert(pthread_mutex_unlock(&fio->wlock));

	return wbuffer;
}
