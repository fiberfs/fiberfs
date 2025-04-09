/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_WORKSPACE_H_INCLUDED_
#define _FBR_WORKSPACE_H_INCLUDED_

#include <stdint.h>
#include <stddef.h>

#define FBR_WORKSPACE_MIN_SIZE			4096
#define FBR_WORKSPACE_OVERFLOW_MAX		(1024 * 64)

struct fbr_workspace_ptr {
	unsigned int				magic;
#define FBR_WORKSPACE_PTR_MAGIC			0xE2E3579F

	void					*data;
	size_t					size;

	struct fbr_workspace_ptr		*next;
};

struct fbr_workspace {
	unsigned int				magic;
#define FBR_WORKSPACE_MAGIC			0xA78F66C6

	unsigned int				reserved:1;
	unsigned int				reserved_ptr:1;
	unsigned int				overflow:1;

	uint8_t					*data;
	size_t					size;
	size_t					pos;
	size_t					free;

	struct fbr_workspace_ptr		*pointers;
	size_t					overflow_len;
};

size_t fbr_workspace_size(void);
struct fbr_workspace *fbr_workspace_init(void *buffer, size_t size);
void fbr_workspace_reset(struct fbr_workspace *workspace);
void fbr_workspace_free(struct fbr_workspace *workspace);
void *fbr_workspace_alloc(struct fbr_workspace *workspace, size_t size);
void *fbr_workspace_rbuffer(struct fbr_workspace *workspace);
size_t fbr_workspace_rlen(struct fbr_workspace *workspace);
void fbr_workspace_ralloc(struct fbr_workspace *workspace, size_t size);
void fbr_workspace_debug(struct fbr_workspace *workspace, fbr_log_f *logger);

#define fbr_workspace_ok(workspace)						\
{										\
	fbr_magic_check(workspace, FBR_WORKSPACE_MAGIC);			\
	assert_dev(workspace->pos + workspace->free == workspace->size);	\
}

#endif /* _FBR_WORKSPACE_H_INCLUDED_ */
