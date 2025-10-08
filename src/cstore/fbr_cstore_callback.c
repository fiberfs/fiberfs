/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

void
fbr_cstore_chunk_read(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_cstore_async_chunk_read(fs, file, chunk);
}

void
fbr_cstore_chunk_delete(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);

	char buffer[FBR_PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, buffer, sizeof(buffer));

	fbr_cstore_io_chunk_delete(fs, filepath.name, chunk->id, chunk->offset);
}

void
fbr_cstore_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file,
    struct fbr_wbuffer *wbuffer)
{
	fbr_cstore_async_wbuffer_write(fs, file, wbuffer);
}

int
fbr_cstore_index_root_write(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_writer *writer, struct fbr_directory *previous)
{
	return fbr_cstore_io_index_root_write(fs, directory, writer, previous);
}

int
fbr_cstore_index_read(struct fbr_fs *fs, struct fbr_directory *directory)
{
	return fbr_cstore_io_index_read(fs, directory);
}

int
fbr_cstore_index_delete(struct fbr_fs *fs, struct fbr_directory *directory)
{
	return fbr_cstore_io_index_delete(fs, directory);
}

fbr_id_t
fbr_cstore_root_read(struct fbr_fs *fs, struct fbr_path_name *dirpath)
{
	return fbr_cstore_io_root_read(fs, dirpath);
}
