/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/store/fbr_store.h"

void
fbr_body_init(struct fbr_body *body)
{
	assert_dev(body);

	for (size_t i = 0; i < FBR_BODY_DEFAULT_CHUNKS; i++) {
		body->chunk_head.chunks[i].magic = FBR_CHUNK_MAGIC;
		assert_dev(body->chunk_head.chunks[i].state == FBR_CHUNK_FREE);
	}
}

static struct fbr_chunk_slab *
_body_chunk_slab_alloc(void)
{
	size_t chunk_size = sizeof(struct fbr_chunk) * FBR_BODY_SLAB_DEFAULT_CHUNKS;
	struct fbr_chunk_slab *slab = calloc(1, sizeof(*slab) + chunk_size);

	slab->magic = FBR_CHUNK_SLAB_MAGIC;
	slab->length = FBR_BODY_SLAB_DEFAULT_CHUNKS;

	for (size_t i = 0; i < slab->length; i++) {
		slab->chunks[i].magic = FBR_CHUNK_MAGIC;
		assert_dev(slab->chunks[i].state == FBR_CHUNK_FREE);
	}

	return slab;
}

static struct fbr_chunk *
_body_chunk_alloc(struct fbr_fs *fs, struct fbr_body *body)
{
	assert_dev(fs);
	assert_dev(body);

	for (size_t i = 0; i < FBR_BODY_DEFAULT_CHUNKS; i++) {
		fbr_chunk_ok(&body->chunk_head.chunks[i]);
		if (body->chunk_head.chunks[i].state == FBR_CHUNK_FREE) {
			return &body->chunk_head.chunks[i];
		}
	}

	struct fbr_chunk_slab *slab = body->chunk_head.next;

	if (slab) {
		fbr_chunk_slab_ok(slab);

		for (size_t i = 0; i < slab->length; i++) {
			fbr_chunk_ok(&slab->chunks[i]);
			if (slab->chunks[i].state == FBR_CHUNK_FREE) {
				return &slab->chunks[i];
			}
		}
	}

	slab = _body_chunk_slab_alloc();
	fbr_chunk_slab_ok(slab);
	assert_dev(slab->length);

	slab->next = body->chunk_head.next;
	body->chunk_head.next = slab;

	fbr_fs_stat_add(&fs->stats.chunk_slabs);

	return &slab->chunks[0];
}

static void
_body_chunk_insert(struct fbr_body *body, struct fbr_chunk *chunk)
{
	assert_dev(body);
	assert_dev(body->chunks);
	assert_dev(chunk);
	assert_zero_dev(chunk->next);

	struct fbr_chunk *prev = NULL;
	struct fbr_chunk *current = body->chunks;

	while (current) {
		fbr_chunk_ok(current);

		size_t current_end = current->offset + current->length;

		// chunk starts before the end of current
		if (chunk->offset < current_end) {
			break;
		}

		prev = current;
		current = current->next;
	}

	assert_dev(current);

	if (!prev) {
		chunk->next = current;
		body->chunks = chunk;
	} else {
		chunk->next = current;
		prev->next = chunk;
	}
}

static struct fbr_chunk *
_body_chunk_add(struct fbr_fs *fs, struct fbr_file *file, fbr_id_t id, size_t offset,
    size_t length, int append)
{
	assert_dev(fs);
	assert_dev(file);
	assert_dev(length);

	struct fbr_chunk *chunk = _body_chunk_alloc(fs, &file->body);
	fbr_chunk_ok(chunk);
	assert_dev(chunk->state == FBR_CHUNK_FREE);
	assert_zero_dev(chunk->next);

	chunk->state = FBR_CHUNK_EMPTY;
	chunk->id = id;
	chunk->offset = offset;
	chunk->length = length;

	if (!file->body.chunks) {
		assert_zero_dev(file->body.chunk_last);
		file->body.chunks = chunk;
		file->body.chunk_last = chunk;
	} else {
		struct fbr_chunk *chunk_last = file->body.chunk_last;
		fbr_chunk_ok(chunk_last);

		size_t last_end = chunk_last->offset + chunk_last->length;

		// chunk starts after the end of the last
		if (chunk->offset >= last_end || append) {
			chunk_last->next = chunk;
			file->body.chunk_last = chunk;
		} else {
			_body_chunk_insert(&file->body, chunk);
		}
	}

	assert_zero_dev(chunk->do_free);
	assert_zero_dev(chunk->data);

	fbr_chunk_ok(chunk);

	size_t chunk_end = chunk->offset + chunk->length;
	if (file->size < chunk_end) {
		fbr_rlog(FBR_LOG_CHUNK, "new file->size: %zu (was: %zu)", chunk_end, file->size);
		file->size = chunk_end;
	}

	return chunk;
}

// Note: if file->state == FBR_FILE_OK, must have file lock
struct fbr_chunk *
fbr_body_chunk_add(struct fbr_fs *fs, struct fbr_file *file, fbr_id_t id, size_t offset,
    size_t length)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(length);

	return _body_chunk_add(fs, file, id, offset, length, 0);
}

struct fbr_chunk *
fbr_body_chunk_append(struct fbr_fs *fs, struct fbr_file *file, fbr_id_t id, size_t offset,
    size_t length)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_INIT);
	assert(length);

	return _body_chunk_add(fs, file, id, offset, length, 1);
}

struct fbr_chunk *
fbr_body_chunk_clone(struct fbr_fs *fs, struct fbr_body *body, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	assert(body);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY);

	struct fbr_chunk *clone = _body_chunk_alloc(fs, body);
	fbr_chunk_ok(clone);
	assert_dev(clone->state == FBR_CHUNK_FREE);
	assert_zero_dev(clone->next);
	assert_zero_dev(clone->data);

	clone->state = FBR_CHUNK_EMPTY;
	clone->id = chunk->id;
	clone->offset = chunk->offset;
	clone->length = chunk->length;

	return clone;
}

// Note: must have body->lock
void
fbr_body_chunk_prune(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk_list *remove)
{
	fbr_fs_ok(fs);
	assert_dev(fs->store);
	fbr_file_ok(file);
	assert(file->state >= FBR_FILE_OK);
	fbr_chunk_list_ok(remove);

	if (!remove->length || !file->body.chunks) {
		return;
	}

	struct fbr_chunk *chunk = file->body.chunks;
	struct fbr_chunk *prev = NULL;
	size_t size = 0;

	while (chunk) {
		fbr_chunk_ok(chunk);

		if (fbr_chunk_list_contains(remove, chunk)) {
			if (prev) {
				prev->next = chunk->next;
			} else {
				file->body.chunks = chunk->next;
			}

			chunk = chunk->next;

			continue;
		}

		size_t chunk_end = chunk->offset + chunk->length;
		if (chunk_end > size) {
			size = chunk_end;
		}

		prev = chunk;
		chunk = chunk->next;
	}

	file->body.chunk_last = prev;

	if (file->size != size) {
		fbr_rlog(FBR_LOG_BODY, "new file->size: %zu (was: %zu)", size, file->size);
		file->size = size;
	}

	for (size_t i = 0; i < remove->length; i++) {
		struct fbr_chunk *chunk = remove->list[i];
		fbr_chunk_ok(chunk);

		if (!chunk->id) {
			continue;
		}

		// TODO async?
		if (fs->store->chunk_delete_f) {
			fs->store->chunk_delete_f(fs, file, chunk);
		}
	}
}

// Note: must have body->lock
struct fbr_chunk_list *
fbr_body_chunk_range(struct fbr_file *file, size_t offset, size_t size,
    struct fbr_chunk_list **removed, struct fbr_wbuffer *wbuffers)
{
	fbr_file_ok(file);
	assert(file->state >= FBR_FILE_OK);
	assert_dev(size <= file->size);

	struct fbr_chunk_list *chunks = fbr_chunk_list_alloc();
	int completed = 0;
	int do_removed = 0;

	if (removed) {
		if (!*removed) {
			*removed = fbr_chunk_list_alloc();
		} else {
			fbr_chunk_list_ok(*removed);
			(*removed)->length = 0;
		}

		do_removed = 1;
	}

	if (!size) {
		assert_zero_dev(offset);
		completed = 1;

		if (!do_removed) {
			return chunks;
		}
	}

	struct fbr_chunk *chunk = file->body.chunks;

	while (chunk) {
		fbr_chunk_ok(chunk);
		assert(chunk->state >= FBR_CHUNK_EMPTY);

		if (wbuffers && chunk->state == FBR_CHUNK_WBUFFER) {
			if (!fbr_wbuffer_has_chunk(wbuffers, chunk)) {
				chunk = chunk->next;
				continue;
			}
		}

		if (!completed && fbr_chunk_in_offset(chunk, offset, size)) {
			if (fbr_chunk_list_complete(chunks, chunk->offset, chunk->length)) {
				if (do_removed) {
					*removed = fbr_chunk_list_add(*removed, chunk);
				}

				chunk = chunk->next;
				continue;
			}

			chunks = fbr_chunk_list_add(chunks, chunk);

			if (fbr_chunk_list_complete(chunks, offset, size)) {
				if (do_removed) {
					completed = 1;
				} else {
					break;
				}
			}
		} else if (do_removed) {
			*removed = fbr_chunk_list_add(*removed, chunk);
		}

		chunk = chunk->next;
	}

	if (fbr_is_dev() && wbuffers) {
		struct fbr_wbuffer *wbuffer = wbuffers;
		while (wbuffer) {
			assert_dev(wbuffer->chunk);
			assert_dev(fbr_chunk_list_contains(chunks, wbuffer->chunk));
			if (do_removed) {
				assert_zero_dev(fbr_chunk_list_contains(*removed, wbuffer->chunk));
			}
			wbuffer = wbuffer->next;
		}
	}

	return chunks;
}

// Note: must have body->lock
struct fbr_chunk_list *
fbr_body_chunk_all(struct fbr_file *file, int include_wbuffers)
{
	fbr_file_ok(file);
	assert(file->state >= FBR_FILE_OK);

	struct fbr_chunk_list *chunks = fbr_chunk_list_alloc();
	struct fbr_chunk *chunk = file->body.chunks;

	while (chunk) {
		fbr_chunk_ok(chunk);
		assert(chunk->state >= FBR_CHUNK_EMPTY);

		if (!include_wbuffers && chunk->state == FBR_CHUNK_WBUFFER) {
			chunk = chunk->next;
			continue;
		}

		chunks = fbr_chunk_list_add(chunks, chunk);

		chunk = chunk->next;
	}

	return chunks;
}

// Note: must have body->lock
unsigned long
fbr_body_length(struct fbr_file *file, struct fbr_wbuffer *wbuffers)
{
	fbr_file_ok(file);

	unsigned long size = 0;

	struct fbr_chunk *chunk = file->body.chunks;
	while (chunk) {
		if (chunk->state == FBR_CHUNK_WBUFFER) {
			chunk = chunk->next;
			continue;
		}

		size_t chunk_end = chunk->offset + chunk->length;
		if (chunk_end > size) {
			size = chunk_end;
		}

		chunk = chunk->next;
	}

	struct fbr_wbuffer *wbuffer = wbuffers;
	while (wbuffer) {
		size_t wbuffer_end = wbuffer->offset + wbuffer->end;
		if (wbuffer_end > size) {
			size = wbuffer_end;
		}

		wbuffer = wbuffer->next;
	}

	return size;
}

// Note: file->lock required
void
fbr_body_debug(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	if (!fbr_is_dev()) {
		return;
	}

	struct fbr_chunk *chunk = file->body.chunks;
	size_t count = 0;
	size_t state[__FBR_CHUNK_STATE_SIZE];
	memset(state, 0, sizeof(state));

	while (chunk) {
		fbr_chunk_ok(chunk);
		assert(chunk->state < __FBR_CHUNK_STATE_SIZE);

		if (count < 3) {
			fbr_rlog(FBR_LOG_DEBUG, "BODY chunk[%zu] state: %s off: %zu len: %zu"
				" id: %lu", count, fbr_chunk_state(chunk->state), chunk->offset,
				chunk->length, chunk->id);
		}

		count++;
		state[chunk->state]++;
		chunk = chunk->next;
	}

	char buffer[500];
	buffer[0] = '\0';

	for (size_t i = 0; i < fbr_array_len(state); i++) {
		strncat(buffer, " ", sizeof(buffer) - strlen(buffer) - 1);
		strncat(buffer, fbr_chunk_state(i), sizeof(buffer) - strlen(buffer) - 1);
		strncat(buffer, ": ", sizeof(buffer) - strlen(buffer) - 1);
		size_t len = strlen(buffer);
		snprintf(buffer + len, sizeof(buffer) - len, "%zu", state[i]);
	}

	if (count > 3) {
		fbr_rlog(FBR_LOG_DEBUG, "BODY ... chunks: %zu%s", count, buffer);
	}
}

static void
_body_chunk_slab_free(struct fbr_chunk_slab *slab)
{
	assert_dev(slab);

	for (size_t i = 0; i < slab->length; i++) {
		struct fbr_chunk *chunk = &slab->chunks[i];
		fbr_chunk_ok(chunk);
		assert_zero_dev(chunk->refcount);
		assert(chunk->state <= FBR_CHUNK_EMPTY);

		fbr_ZERO(chunk);
	}

	free(slab);
}

void
fbr_body_free(struct fbr_body *body)
{
	assert_dev(body);

	for (size_t i = 0; i < FBR_BODY_DEFAULT_CHUNKS; i++) {
		struct fbr_chunk *chunk = &body->chunk_head.chunks[i];
		fbr_chunk_ok(chunk);
		assert_zero(chunk->refcount);
		assert(chunk->state <= FBR_CHUNK_EMPTY);
	}

	while (body->chunk_head.next) {
		struct fbr_chunk_slab *slab = body->chunk_head.next;
		fbr_chunk_slab_ok(slab);

		body->chunk_head.next = slab->next;

		_body_chunk_slab_free(slab);
	}

	fbr_ZERO(body);
}
