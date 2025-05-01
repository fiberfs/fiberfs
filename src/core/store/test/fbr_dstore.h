/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_DSTORE_H_INCLUDED_
#define _FBR_DSTORE_H_INCLUDED_

#include "utils/fbr_id.h"

struct fbr_test_context;
struct fbr_fs;
struct fbr_file;
struct fbr_wbuffer;
struct fbr_chunk;

void fbr_dstore_init(struct fbr_test_context *ctx);
void fbr_dstore_wbuffer(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer);
void fbr_dstore_fetch(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk);
void fbr_dstore_index(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_writer *writer);
int fbr_dstore_root(struct fbr_fs *fs, struct fbr_directory *directory, fbr_id_t existing);

#endif /* _FBR_DSTORE_H_INCLUDED_ */
