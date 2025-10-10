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
	fbr_cstore_io_chunk_read(fs, file, chunk);
}

void
fbr_cstore_chunk_delete(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return;
	}

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_cstore_s3_chunk_url(cstore, file, chunk, url, sizeof(url));

	fbr_cstore_io_delete_url(cstore, url, url_len, chunk->id, FBR_CSTORE_FILE_CHUNK);
}

void
fbr_cstore_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file,
    struct fbr_wbuffer *wbuffer)
{
	fbr_cstore_io_wbuffer_write(fs, file, wbuffer);
}

int
fbr_cstore_index_root_write(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_writer *writer, struct fbr_directory *previous)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	fbr_writer_ok(writer);
	assert_dev(writer->output);

	int ret = fbr_cstore_io_index_write(fs, directory, writer);
	if (ret) {
		return ret;
	}

	fbr_id_t previous_version = 0;
	if (previous) {
		fbr_directory_ok(previous);
		assert(previous->version);
		previous_version = previous->version;
	}

	ret = fbr_cstore_io_root_write(fs, directory, previous_version);
	if (ret) {
		fbr_cstore_io_index_remove(fs, directory);
	} else if (previous) {
		fbr_cstore_async_index_remove(fs, previous);
	}

	return ret;
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
