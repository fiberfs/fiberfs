/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"

static void
_chunk_reset(struct fbr_chunk *chunk)
{
	assert_dev(chunk);
	assert_zero_dev(chunk->refcount);

	if (chunk->state == FBR_CHUNK_SPLICED) {
		assert_dev(chunk->fd_splice_ok);
		assert_zero_dev(chunk->data);
	} else {
		assert_dev(chunk->state == FBR_CHUNK_READY);
		assert_dev(chunk->data);
		free(chunk->data);
	}

	chunk->state = FBR_CHUNK_EMPTY;
	chunk->fd_splice_ok = 0;
	chunk->data = NULL;
	chunk->chttp_splice = NULL;
}

void
fbr_chunk_take(struct fbr_chunk *chunk) {
	fbr_chunk_ok(chunk);

	fbr_refcount_t refs = fbr_atomic_add(&chunk->refcount, 1);
	assert(refs);

	assert_dev(refs == 1 || chunk->state == FBR_CHUNK_READY);
}

void
fbr_chunk_release(struct fbr_chunk *chunk) {
	fbr_chunk_ok(chunk);
	assert_dev(chunk->state != FBR_CHUNK_LOADING);

	assert(chunk->refcount);
	fbr_refcount_t refs = fbr_atomic_sub(&chunk->refcount, 1);

	if (refs) {
		return;
	}

	if (chunk->state == FBR_CHUNK_READY || chunk->state == FBR_CHUNK_SPLICED) {
		_chunk_reset(chunk);
		assert_dev(chunk->state == FBR_CHUNK_EMPTY);
	}
}

int
fbr_chunk_in_offset(struct fbr_chunk *chunk, size_t offset, size_t size)
{
	assert_dev(chunk);

	size_t offset_end = offset + size;
	size_t chunk_end = chunk->offset + chunk->length;

	// Offset is inside chunk
	if (offset >= chunk->offset && offset < chunk_end) {
		return 1;
	}
	// Chunk is inside offset
	if (offset < chunk->offset && offset_end > chunk->offset) {
		return 1;
	}

	return 0;
}

const char *
fbr_chunk_state(enum fbr_chunk_state state)
{
	switch (state) {
		case FBR_CHUNK_NONE:
			return "NONE";
		case FBR_CHUNK_EMPTY:
			return "EMPTY";
		case FBR_CHUNK_LOADING:
			return "LOADING";
		case FBR_CHUNK_READY:
			return "READY";
		case FBR_CHUNK_SPLICED:
			return "SPLICE";
		case FBR_CHUNK_WBUFFER:
			return "WBUFFER";
	}

	return "ERROR";
}

struct fbr_chunk_list *
fbr_chunk_list_alloc(void)
{
	struct fbr_chunk_list *chunks;

	chunks = malloc(sizeof(*chunks) + (sizeof(*chunks->list) * FBR_BODY_DEFAULT_CHUNKS));
	assert(chunks);

	chunks->magic = FBR_CHUNK_LIST_MAGIC;
	chunks->capacity = FBR_BODY_DEFAULT_CHUNKS;
	chunks->length = 0;

	return chunks;
}

struct fbr_chunk_list *
fbr_chunk_list_expand(struct fbr_chunk_list *chunks)
{
	fbr_chunk_list_ok(chunks);
	assert(chunks->capacity);
	assert(chunks->capacity < FUSE_IOCTL_MAX_IOV);

	chunks->capacity *= 2;

	chunks = realloc(chunks, sizeof(*chunks) + (sizeof(*chunks->list) * chunks->capacity));
	assert(chunks);

	return chunks;
}

void
fbr_chunk_list_debug(struct fbr_fs *fs, struct fbr_chunk_list *chunks, const char *name)
{
	assert_dev(fs);
	assert_dev(fs->logger);
	assert_dev(chunks);

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);
		fs->log("%s chunk[%zu] state: %s, data: %p off: %zu len: %zu id: %lu",
			name, i, fbr_chunk_state(chunk->state), (void*)chunk->data,
			chunk->offset, chunk->length, chunk->id);
	}
}

struct fbr_chunk_list *
fbr_chunk_list_add(struct fbr_chunk_list *chunks, struct fbr_chunk *chunk)
{
	assert_dev(chunks);
	assert_dev(chunk);

	if (chunks->length == chunks->capacity) {
		chunks = fbr_chunk_list_expand(chunks);
	}
	assert_dev(chunks->length < chunks->capacity);

	chunks->list[chunks->length] = chunk;
	chunks->length++;

	return chunks;
}

int
fbr_chunk_list_contains(struct fbr_chunk_list *chunks, struct fbr_chunk *chunk)
{
	assert_dev(chunks);
	assert_dev(chunk);

	for (size_t i = 0; i < chunks->length; i++) {
		if (chunks->list[i] == chunk) {
			return 1;
		}
	}

	return 0;
}

struct fbr_chunk *
fbr_chunk_list_find(struct fbr_chunk_list *chunks, size_t offset)
{
	assert_dev(chunks);

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);
		assert_dev(chunk->length);

		size_t chunk_end = chunk->offset + chunk->length;

		// chunk starts at or before offset
		if (chunk->offset <= offset && chunk_end > offset) {
			return chunk;
		}
	}

	return NULL;
}

struct fbr_chunk *
fbr_chunk_list_next(struct fbr_chunk_list *chunks, size_t offset)
{
	assert_dev(chunks);

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

static int
_chunk_list_complete(struct fbr_chunk_list *chunks, size_t offset, size_t size)
{
	assert_dev(chunks);

	size_t offset_end = offset + size;

	while (offset < offset_end) {
		struct fbr_chunk *chunk = fbr_chunk_list_find(chunks, offset);
		if (!chunk) {
			return 0;
		}

		offset = chunk->offset + chunk->length;
	}

	return 1;
}

struct fbr_chunk_list *
fbr_chunk_list_file(struct fbr_file *file, size_t offset, size_t size)
{
	fbr_file_ok(file);

	struct fbr_chunk_list *chunks = fbr_chunk_list_alloc();
	struct fbr_chunk *chunk = file->body.chunks;

	while (chunk) {
		fbr_chunk_ok(chunk);
		assert(chunk->state >= FBR_CHUNK_EMPTY);

		if (fbr_chunk_in_offset(chunk, offset, size)) {

			if (_chunk_list_complete(chunks, chunk->offset, chunk->length)) {
				chunk = chunk->next;
				continue;
			}

			chunks = fbr_chunk_list_add(chunks, chunk);

			if (_chunk_list_complete(chunks, offset, size)) {
				break;
			}
		}

		chunk = chunk->next;
	}

	return chunks;
}

void
fbr_chunk_list_free(struct fbr_chunk_list *chunks)
{
	fbr_chunk_list_ok(chunks);

	fbr_ZERO(chunks);
	free(chunks);
}
