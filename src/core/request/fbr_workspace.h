/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_WORKSPACE_H_INCLUDED_
#define _FBR_WORKSPACE_H_INCLUDED_

#include <stddef.h>

#define FBR_WORKSPACE_MIN_SIZE			4096
#define FBR_WORKSPACE_OVERFLOW_MAX		(1024 * 64)

struct fbr_workspace;

size_t fbr_workspace_size(void);
struct fbr_workspace *fbr_workspace_init(void *buffer, size_t size);
void fbr_workspace_reset(struct fbr_workspace *workspace);
void fbr_workspace_free(struct fbr_workspace *workspace);
void *fbr_workspace_alloc(struct fbr_workspace *workspace, size_t size);
void *fbr_workspace_rbuffer(struct fbr_workspace *workspace);
size_t fbr_workspace_rlen(struct fbr_workspace *workspace);
void fbr_workspace_ralloc(struct fbr_workspace *workspace, size_t size);

#endif /* _FBR_WORKSPACE_H_INCLUDED_ */
