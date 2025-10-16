/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_CALLBACK_H_INCLUDED_
#define _FBR_CSTORE_CALLBACK_H_INCLUDED_

#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

extern const struct fbr_store_callbacks *FBR_CSTORE_DEFAULT_CALLBACKS;

void fbr_cstore_chunk_read(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk);
void fbr_cstore_chunk_delete(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk);
void fbr_cstore_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_wbuffer *wbuffer);
int fbr_cstore_index_root_write(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_writer *writer, struct fbr_directory *previous);
int fbr_cstore_index_read(struct fbr_fs *fs, struct fbr_directory *directory);
int fbr_cstore_index_delete(struct fbr_fs *fs, struct fbr_directory *directory);
fbr_id_t fbr_cstore_root_read(struct fbr_fs *fs, struct fbr_path_name *dirpath, int fresh);

#endif /* _FBR_CSTORE_CALLBACK_H_INCLUDED_ */
