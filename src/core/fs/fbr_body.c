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

void
fbr_body_init(struct fbr_body *body)
{
	assert_dev(body);

	pt_assert(pthread_mutex_init(&body->lock, NULL));
	pt_assert(pthread_cond_init(&body->update, NULL));

	for (size_t i = 0; i < FBR_BODY_DEFAULT_CHUNKS; i++) {
		body->slabhead.chunks[i].magic = FBR_CHUNK_MAGIC;
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
	}

	return slab;
}

static struct fbr_chunk *
_body_chunk_alloc(struct fbr_body *body)
{
	assert_dev(body);

	for (size_t i = 0; i < FBR_BODY_DEFAULT_CHUNKS; i++) {
		fbr_chunk_ok(&body->slabhead.chunks[i]);
		if (body->slabhead.chunks[i].state == FBR_CHUNK_NONE) {
			return &body->slabhead.chunks[i];
		}
	}

	struct fbr_chunk_slab *slab = body->slabhead.next;

	if (slab) {
		fbr_chunk_slab_ok(slab);

		for (size_t i = 0; i < slab->length; i++) {
			fbr_chunk_ok(&slab->chunks[i]);
			if (slab->chunks[i].state == FBR_CHUNK_NONE) {
				return &slab->chunks[i];
			}
		}
	}

	slab = _body_chunk_slab_alloc();
	fbr_chunk_slab_ok(slab);
	assert(slab->length);

	slab->next = body->slabhead.next;
	body->slabhead.next = slab;

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
		body->chunks = chunk;
		chunk->next = current;
	} else {
		prev->next = chunk;
		chunk->next = current;
	}
}

struct fbr_chunk *
fbr_body_chunk_add(struct fbr_file *file, fbr_id_t id, size_t offset, size_t length)
{
	fbr_file_ok(file);
	// TODO exiting file?
	assert(file->state == FBR_FILE_INIT);
	assert(length);

	struct fbr_chunk *chunk = _body_chunk_alloc(&file->body);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_NONE);
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
		if (chunk->offset >= last_end) {
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
		file->size = chunk_end;
	}

	return chunk;
}

void
fbr_body_LOCK(struct fbr_fs *fs, struct fbr_body *body)
{
	fbr_fs_ok(fs);
	assert(body);
	fbr_fuse_lock(fs->fuse_ctx, &body->lock);
}

void
fbr_body_UNLOCK(struct fbr_body *body)
{
	assert(body);
	pt_assert(pthread_mutex_unlock(&body->lock));
}

void
fbr_body_debug(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	assert_dev(fs->logger);
	fbr_file_ok(file);

	struct fbr_chunk *chunk = file->body.chunks;
	size_t i = 0;

	while (chunk) {
		fbr_chunk_ok(chunk);
		fs->log("BODY chunk[%zu] state: %s off: %zu len: %zu id: %lu", i,
			fbr_chunk_state(chunk->state), chunk->offset, chunk->length, chunk->id);
		chunk = chunk->next;
		i++;
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
	}

	size_t chunk_size = sizeof(struct fbr_chunk) * slab->length;
	explicit_bzero(slab, sizeof(*slab) + chunk_size);

	free(slab);
}

void
fbr_body_free(struct fbr_body *body)
{
	assert_dev(body);

	pt_assert(pthread_mutex_destroy(&body->lock));
	pt_assert(pthread_cond_destroy(&body->update));

	for (size_t i = 0; i < FBR_BODY_DEFAULT_CHUNKS; i++) {
		struct fbr_chunk *chunk = &body->slabhead.chunks[i];
		fbr_chunk_ok(chunk);
		assert_zero(chunk->refcount);
		assert(chunk->state <= FBR_CHUNK_EMPTY);
	}

	while (body->slabhead.next) {
		struct fbr_chunk_slab *slab = body->slabhead.next;
		fbr_chunk_slab_ok(slab);

		body->slabhead.next = slab->next;

		_body_chunk_slab_free(slab);
	}

	fbr_ZERO(body);
}
