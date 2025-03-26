/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_DSTORE_H_INCLUDED_
#define _FBR_DSTORE_H_INCLUDED_

struct fbr_test_context;
struct fbr_file;
struct fbr_wbuffer;
struct fbr_chunk;

void fbr_dstore_init(struct fbr_test_context *ctx);
void fbr_dstore_wbuffer(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer);
void fbr_dstore_fetch(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk);

#endif /* _FBR_DSTORE_H_INCLUDED_ */
