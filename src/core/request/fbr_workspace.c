/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdint.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_workspace.h"

#define _WORKSPACE_SIZE				(1024 * 16)
#define _WORKSPACE_MIN_SIZE			(sizeof(struct fbr_workspace) + \
							FBR_WORKSPACE_MIN_SIZE)

size_t
fbr_workspace_size(void)
{
	assert_dev(_WORKSPACE_SIZE > _WORKSPACE_MIN_SIZE);

	// TODO make this a config param
	return sizeof(struct fbr_workspace) + _WORKSPACE_SIZE;
}

struct fbr_workspace *
fbr_workspace_init(void *buffer, size_t size)
{
	assert(buffer);
	assert(size >= _WORKSPACE_MIN_SIZE);

	struct fbr_workspace *workspace = (struct fbr_workspace*)buffer;

	fbr_zero(workspace);
	workspace->magic = FBR_WORKSPACE_MAGIC;
	workspace->data = (uint8_t*)(workspace + 1);
	workspace->size = size - sizeof(*workspace);
	workspace->free = workspace->size;

	fbr_workspace_ok(workspace);

	return workspace;
}

void
fbr_workspace_reset(struct fbr_workspace *workspace)
{
	fbr_workspace_ok(workspace);

	struct fbr_workspace_ptr *ptr = workspace->pointers;

	while (ptr) {
		fbr_magic_check(ptr, FBR_WORKSPACE_PTR_MAGIC);

		struct fbr_workspace_ptr *next = ptr->next;

		fbr_zero(ptr);
		free(ptr);

		ptr = next;
	}

	workspace->pointers = NULL;
	workspace->free = workspace->size;
	workspace->pos = 0;
	workspace->overflow_len = 0;
	workspace->reserved = 0;
	workspace->reserved_ptr = 0;
}

void
fbr_workspace_free(struct fbr_workspace *workspace)
{
	fbr_workspace_ok(workspace);

	fbr_workspace_reset(workspace);
	fbr_zero(workspace);
}

static void *
_workspace_malloc(struct fbr_workspace *workspace, size_t size)
{
	fbr_workspace_ok(workspace);
	assert_dev(size);
	assert_dev(size <= FBR_WORKSPACE_OVERFLOW_MAX);
	assert_dev(size > workspace->free);

	struct fbr_workspace_ptr *ptr = malloc(sizeof(*ptr) + size);
	assert(ptr);

	ptr->magic = FBR_WORKSPACE_PTR_MAGIC;
	ptr->data = ptr + 1;
	ptr->size = size;
	ptr->next = workspace->pointers;

	workspace->pointers = ptr;
	workspace->overflow_len += size;

	return ptr->data;
}

static int
_workspace_full(struct fbr_workspace *workspace, size_t alloc_size)
{
	assert_dev(workspace);

	if (alloc_size < workspace->free) {
		return 0;
	} else if (workspace->overflow_len > FBR_WORKSPACE_OVERFLOW_MAX) {
		return 1;
	} else if (alloc_size > FBR_WORKSPACE_OVERFLOW_MAX) {
		return 1;
	}

	return 0;
}

void *
fbr_workspace_alloc(struct fbr_workspace *workspace, size_t size)
{
	fbr_workspace_ok(workspace);
	assert_zero(workspace->reserved);
	assert_zero_dev(workspace->reserved_ptr);
	assert(size);

	if (_workspace_full(workspace, size)) {
		return NULL;
	}

	if (size > workspace->free) {
		return _workspace_malloc(workspace, size);
	}

	void *data = workspace->data + workspace->pos;
	workspace->pos += size;
	workspace->free -= size;
	assert_dev(workspace->pos <= workspace->size);

	return data;
}

void *
fbr_workspace_rbuffer(struct fbr_workspace *workspace)
{
	fbr_workspace_ok(workspace);
	assert_zero(workspace->reserved);
	assert_zero_dev(workspace->reserved_ptr);

	if (_workspace_full(workspace, FBR_WORKSPACE_MIN_SIZE)) {
		return NULL;
	}

	workspace->reserved = 1;

	if (workspace->free < FBR_WORKSPACE_MIN_SIZE) {
		workspace->reserved_ptr = 1;
		return _workspace_malloc(workspace, FBR_WORKSPACE_MIN_SIZE);
	}

	return workspace->data + workspace->pos;
}

size_t
fbr_workspace_rlen(struct fbr_workspace *workspace)
{
	fbr_workspace_ok(workspace);

	if (!workspace->reserved) {
		return 0;
	}

	if (workspace->reserved_ptr) {
		assert_dev(workspace->free < FBR_WORKSPACE_MIN_SIZE);
		return FBR_WORKSPACE_MIN_SIZE;
	}

	return workspace->free;
}

void
fbr_workspace_ralloc(struct fbr_workspace *workspace, size_t size)
{
	fbr_workspace_ok(workspace);
	assert(workspace->reserved);

	workspace->reserved = 0;

	if (workspace->reserved_ptr) {
		assert(size <= FBR_WORKSPACE_MIN_SIZE);
		workspace->reserved_ptr = 0;
		return;
	}

	assert(size <= workspace->free);
	workspace->pos += size;
	workspace->free -= size;
	assert_dev(workspace->pos <= workspace->size);
}

void
fbr_workspace_debug(struct fbr_workspace *workspace, fbr_log_f *logger)
{
	fbr_workspace_ok(workspace);
	assert(logger);

	// TODO address the newlines with a proper logger

	logger("workspace.reserved=%u\n", workspace->reserved);
	logger("workspace.reserved_ptr=%u\n", workspace->reserved_ptr);
	logger("workspace.size=%zu\n", workspace->size);
	logger("workspace.pos=%zu\n", workspace->pos);
	logger("workspace.free=%zu\n", workspace->free);
	logger("workspace.overflow_len=%zu\n", workspace->overflow_len);

	struct fbr_workspace_ptr *ptr = workspace->pointers;
	while (ptr) {
		fbr_magic_check(ptr, FBR_WORKSPACE_PTR_MAGIC);
		logger("workspace.ptr.size=%zu\n", ptr->size);
		ptr = ptr->next;
	}
}
