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
	fbr_chunk_ok(chunk);
	assert_zero(chunk->refcount);
	assert(chunk->state != FBR_CHUNK_LOADING);

	switch (chunk->state) {
		case FBR_CHUNK_READY:
		case FBR_CHUNK_WBUFFER:
			if (chunk->do_free) {
				assert_dev(chunk->data);
				free(chunk->data);
			}
			break;
		case FBR_CHUNK_SPLICED:
			assert_dev(chunk->fd_splice_ok);
			assert_zero_dev(chunk->data);
			break;
		default:
			break;
	}

	chunk->state = FBR_CHUNK_EMPTY;
	chunk->fd_splice_ok = 0;
	chunk->do_free = 0;
	chunk->data = NULL;
	chunk->chttp_splice = NULL;
}

// Note: file->lock required
void
fbr_chunk_take(struct fbr_chunk *chunk)
{
	fbr_chunk_ok(chunk);
	assert(chunk->state >= FBR_CHUNK_EMPTY);

	chunk->refcount++;
	assert(chunk->refcount);
}

// Note: file->lock required
void
fbr_chunk_release(struct fbr_chunk *chunk)
{
	fbr_chunk_ok(chunk);
	assert(chunk->state >= FBR_CHUNK_EMPTY);

	assert(chunk->refcount);
	chunk->refcount--;

	if (chunk->refcount) {
		return;
	}

	_chunk_reset(chunk);
}

int
fbr_chunk_in_offset(struct fbr_chunk *chunk, size_t offset, size_t size)
{
	fbr_chunk_ok(chunk);

	size_t offset_end = offset + size;
	size_t chunk_end = chunk->offset + chunk->length;

	// offset is inside chunk
	if (offset >= chunk->offset && offset < chunk_end) {
		return 1;
	}
	// chunk is inside offset
	if (offset < chunk->offset && offset_end > chunk->offset) {
		return 1;
	}

	return 0;
}

const char *
fbr_chunk_state(enum fbr_chunk_state state)
{
	switch (state) {
		case FBR_CHUNK_FREE:
			return "FREE";
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
		case __FBR_CHUNK_STATE_SIZE:
			break;
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
	assert(chunks->capacity < UINT32_MAX);

	chunks->capacity *= 2;

	chunks = realloc(chunks, sizeof(*chunks) + (sizeof(*chunks->list) * chunks->capacity));
	assert(chunks);

	return chunks;
}

void
fbr_chunk_list_debug(struct fbr_fs *fs, struct fbr_chunk_list *chunks, const char *name)
{
	fbr_fs_ok(fs);
	fbr_chunk_list_ok(chunks);

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);
		fbr_rlog(FBR_LOG_DEBUG, "%s chunk[%zu] state: %s, data: %p off: %zu"
			" len: %zu id: %lu",
			name, i, fbr_chunk_state(chunk->state), (void*)chunk->data,
			chunk->offset, chunk->length, chunk->id);
	}
}

struct fbr_chunk_list *
fbr_chunk_list_add(struct fbr_chunk_list *chunks, struct fbr_chunk *chunk)
{
	fbr_chunk_list_ok(chunks);
	fbr_chunk_ok(chunk);

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
	fbr_chunk_list_ok(chunks);
	fbr_chunk_ok(chunk);

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
	fbr_chunk_list_ok(chunks);

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

int
fbr_chunk_list_complete(struct fbr_chunk_list *chunks, size_t offset, size_t size)
{
	fbr_chunk_list_ok(chunks);

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

size_t
fbr_chunk_list_size(struct fbr_chunk_list *chunks)
{
	fbr_chunk_list_ok(chunks);

	size_t size = 0;

	for (size_t i = 0; i < chunks->length; i++) {
		struct fbr_chunk *chunk = chunks->list[i];
		fbr_chunk_ok(chunk);

		size_t chunk_end = chunk->offset + chunk->length;

		if (chunk_end > size) {
			size = chunk_end;
		}
	}

	return size;
}

void
fbr_chunk_list_free(struct fbr_chunk_list *chunks)
{
	fbr_chunk_list_ok(chunks);

	fbr_ZERO(chunks);
	free(chunks);
}
