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

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 1;
	}

	int fail = fbr_cstore_io_index_write(fs, directory, writer);
	if (fail) {
		return fail;
	}

	fbr_id_t previous_version = 0;
	if (previous) {
		fbr_directory_ok(previous);
		assert(previous->version);
		previous_version = previous->version;
	}

	char root_path[FBR_PATH_MAX];
	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);
	fbr_cstore_path_root(NULL, &dirpath, 0, root_path, sizeof(root_path));

	struct fbr_writer *root_json = fbr_writer_alloc_dynamic(fs, FBR_ROOT_JSON_SIZE);
	fbr_root_json_gen(fs, root_json, directory->version);
	assert_zero(root_json->error);

	if (fbr_cstore_backend_enabled(cstore)) {
		fail = fbr_cstore_s3_root_write(cstore, root_json, root_path, directory->version,
			previous_version);
	} else {
		fail = fbr_cstore_io_root_write(cstore, root_json, root_path, directory->version,
			previous_version, 1);
	}

	if (fail) {
		fbr_cstore_io_index_remove(fs, directory);
	} else if (previous) {
		fbr_cstore_async_index_remove(fs, previous);
	}

	return fail;
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
fbr_cstore_root_read(struct fbr_fs *fs, struct fbr_path_name *dirpath, int fresh)
{
	fbr_fs_ok(fs);
	(void)fresh;

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 0;
	}

	fbr_id_t version = 0;
	int has_backend = fbr_cstore_backend_enabled(cstore);

	// TODO if fresh, read local and attempt a conditional?

	if (!fresh || !has_backend) {
		version = fbr_cstore_io_root_read(cstore, dirpath);
	}

	if (!version && has_backend) {
		version = fbr_cstore_s3_root_read(fs, cstore, dirpath);
	}

	return version;
}
