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
struct fbr_directory;
struct fbr_path_name;
struct fbr_wbuffer;
struct fbr_chunk;
struct fbr_writer;

void fbr_dstore_init(struct fbr_test_context *ctx);
void fbr_dstore_debug(int show_meta);
fbr_stats_t fbr_dstore_stat_chunks(void);
void fbr_dstore_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_wbuffer *wbuffer);
void fbr_dstore_chunk_read(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk);
void fbr_dstore_chunk_delete(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk);
void fbr_dstore_index_write(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_writer *writer);
int fbr_dstore_index_read(struct fbr_fs *fs, struct fbr_directory *directory);
void fbr_dstore_index_delete(struct fbr_fs *fs, struct fbr_directory *directory);
int fbr_dstore_index_root_write(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_writer *writer, struct fbr_directory *previous);
int fbr_dstore_root_write(struct fbr_fs *fs, struct fbr_directory *directory, fbr_id_t existing);
fbr_id_t fbr_dstore_root_read(struct fbr_fs *fs, struct fbr_path_name *dirpath);

#endif /* _FBR_DSTORE_H_INCLUDED_ */
