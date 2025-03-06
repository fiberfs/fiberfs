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

	assert_zero(pthread_mutex_init(&body->lock, NULL));
	assert_zero(pthread_cond_init(&body->update, NULL));

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
_body_chunk_get(struct fbr_body *body)
{
	assert_dev(body);

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

void
fbr_body_chunk_add(struct fbr_file *file, fbr_id_t id, size_t offset, size_t length)
{
	fbr_file_ok(file);
	assert(id);
	assert(length);

	struct fbr_chunk *chunk = NULL;

	for (size_t i = 0; i < FBR_BODY_DEFAULT_CHUNKS; i++) {
		fbr_chunk_ok(&file->body.slabhead.chunks[i]);
		if (file->body.slabhead.chunks[i].state == FBR_CHUNK_NONE) {
			chunk = &file->body.slabhead.chunks[i];
			break;
		}
	}

	if (!chunk) {
		chunk = _body_chunk_get(&file->body);
	}

	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_NONE);

	chunk->state = FBR_CHUNK_EMPTY;
	chunk->id = id;
	chunk->offset = offset;
	chunk->length = length;

	if (!file->body.chunks) {
		assert_zero(file->body.chunk_ptr);
		file->body.chunks = chunk;
	} else {
		fbr_chunk_ok(file->body.chunk_ptr);
		file->body.chunk_ptr->next = chunk;
	}

	file->body.chunk_ptr = chunk;
	assert_zero(chunk->next);
	assert_zero(chunk->data);
}

void
fbr_body_LOCK(struct fbr_body *body)
{
	assert(body);
	assert_zero(pthread_mutex_lock(&body->lock));
}

void
fbr_body_UNLOCK(struct fbr_body *body)
{
	assert(body);
	assert_zero(pthread_mutex_unlock(&body->lock));
}

static void
_chunk_empty(struct fbr_chunk *chunk)
{
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_READY);
	assert_zero(chunk->refcount);
	assert(chunk->data);

	if (chunk->fd_spliced) {
		assert_dev(chunk->fd_splice_ok);
		assert_zero_dev(chunk->data);
	} else {
		assert_dev(chunk->data);
		free(chunk->data);
	}

	chunk->state = FBR_CHUNK_EMPTY;
	chunk->fd_splice_ok = 0;
	chunk->fd_spliced = 0;
	chunk->data = NULL;
	chunk->chttp = NULL;
}

void
fbr_chunk_take(struct fbr_chunk *chunk) {
	fbr_chunk_ok(chunk);

	chunk->refcount++;
	assert(chunk->refcount);
}

void
fbr_chunk_release(struct fbr_chunk *chunk) {
	fbr_chunk_ok(chunk);

	assert(chunk->refcount);
	chunk->refcount--;

	if (chunk->refcount && !chunk->fd_spliced) {
		return;
	}

	if (chunk->state == FBR_CHUNK_READY) {
		_chunk_empty(chunk);
	}

	assert(chunk->state == FBR_CHUNK_EMPTY);
}

static void
_body_chunk_slab_free(struct fbr_chunk_slab *slab)
{
	fbr_chunk_slab_ok(slab);

	if (fbr_assert_is_dev()) {
		for (size_t i = 0; i < slab->length; i++) {
			fbr_chunk_ok(&slab->chunks[i]);
			assert_zero(slab->chunks[i].refcount);
		}
	}

	size_t chunk_size = sizeof(struct fbr_chunk) * slab->length;
	explicit_bzero(slab, sizeof(*slab) + chunk_size);

	free(slab);
}

void
fbr_body_free(struct fbr_body *body)
{
	assert_dev(body);

	assert_zero(pthread_mutex_destroy(&body->lock));
	assert_zero(pthread_cond_destroy(&body->update));

	if (fbr_assert_is_dev()) {
		for (size_t i = 0; i < FBR_BODY_DEFAULT_CHUNKS; i++) {
			fbr_chunk_ok(&body->slabhead.chunks[i]);
			assert_zero(body->slabhead.chunks[i].refcount);
		}
	}

	while (body->slabhead.next) {
		struct fbr_chunk_slab *slab = body->slabhead.next;
		fbr_chunk_slab_ok(slab);

		body->slabhead.next = slab->next;

		_body_chunk_slab_free(slab);
	}

	fbr_ZERO(body);
}
