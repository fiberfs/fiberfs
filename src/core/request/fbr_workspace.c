/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdint.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_workspace.h"

struct _workspace_ptr {
	unsigned int				magic;
#define _WORKSPACE_PTR_MAGIC			0xE2E3579F

	void					*data;
	struct _workspace_ptr			*next;
};

struct fbr_workspace {
	unsigned int				magic;
#define _WORKSPACE_MAGIC			0xA78F66C6

	unsigned int				reserved:1;
	unsigned int				reserved_ptr:1;
	unsigned int				overflow:1;
	unsigned int				error:1;

	uint8_t					*data;
	size_t					size;
	size_t					pos;
	size_t					free;

	struct _workspace_ptr			*pointers;
	size_t					overflow_len;
};

#define _WORKSPACE_SIZE				(1024 * 16)
#define _WORKSPACE_MIN_SIZE			(sizeof(struct fbr_workspace) + \
							FBR_WORKSPACE_MIN_SIZE)

#define _workspace_ok(workspace)						\
{										\
	fbr_magic_check(workspace, _WORKSPACE_MAGIC);				\
	assert_dev(workspace->pos + workspace->free == workspace->size);	\
}

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

	fbr_ZERO(workspace);
	workspace->magic = _WORKSPACE_MAGIC;
	workspace->data = (uint8_t*)buffer + sizeof(*workspace);
	workspace->size = size - sizeof(*workspace);
	workspace->free = workspace->size;

	_workspace_ok(workspace);

	return workspace;
}

void
fbr_workspace_reset(struct fbr_workspace *workspace)
{
	_workspace_ok(workspace);

	struct _workspace_ptr *ptr = workspace->pointers;
	while (ptr) {
		struct _workspace_ptr *next = ptr->next;

		fbr_ZERO(ptr);
		free(ptr);

		ptr = next;
	}

	workspace->pointers = NULL;
	workspace->free = workspace->size;
	workspace->pos = 0;
}

void
fbr_workspace_free(struct fbr_workspace *workspace)
{
	_workspace_ok(workspace);

	fbr_workspace_reset(workspace);
	fbr_ZERO(workspace);
}

static void *
_workspace_malloc(struct fbr_workspace *workspace, size_t size)
{
	_workspace_ok(workspace);
	assert_dev(size);
	assert_dev(size <= FBR_WORKSPACE_OVERFLOW_MAX);
	assert_dev(size > workspace->free);

	struct _workspace_ptr *ptr = malloc(sizeof(*ptr) + size);
	assert(ptr);

	ptr->magic = _WORKSPACE_PTR_MAGIC;
	ptr->data = (char*)ptr + sizeof(*ptr);
	ptr->next = workspace->pointers;

	workspace->pointers = ptr;
	workspace->overflow = 1;
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
	_workspace_ok(workspace);
	assert_zero(workspace->reserved);
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
	_workspace_ok(workspace);
	assert_zero(workspace->reserved);

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
	_workspace_ok(workspace);

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
	_workspace_ok(workspace);
	assert(workspace->reserved);

	workspace->reserved = 0;

	if (workspace->reserved_ptr) {
		workspace->reserved_ptr = 0;
		return;
	}

	assert(size <= workspace->free);
	workspace->pos += size;
	workspace->free -= size;
	assert_dev(workspace->pos <= workspace->size);
}
