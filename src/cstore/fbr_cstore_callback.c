/*
 * Copyright (c) 2024-2026 FiberFS LLC
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

	if (!fs->cstore) {
		return;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	struct fbr_cstore_url url;
	fbr_cstore_s3_chunk_url(cstore, file, chunk, &url);

	fbr_cstore_io_delete_url(cstore, &url, NULL, FBR_CSTORE_FILE_CHUNK);
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
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_writer_ok(writer);
	assert_dev(writer->output);

	if (!fs->cstore) {
		return 1;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	int fail = fbr_cstore_io_index_write(fs, directory, writer);
	if (fail) {
		if (fbr_cstore_http_conflict(fail)) {
			return EAGAIN;
		}

		return EIO;
	}

	// TODO we can delay wbuffer upload completion to here
	// see: fbr_wbuffer_flush_store()

	char *etag_match = NULL;
	if (previous) {
		fbr_directory_ok(previous);
		assert(previous->etag.length);
		etag_match = previous->etag.value;
	}

	struct fbr_cstore_path root_path;
	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);
	fbr_cstore_path_root(&dirpath, &root_path);

	struct fbr_writer *root_json = fbr_writer_alloc_dynamic(fs, FBR_ROOT_JSON_SIZE);
	fbr_root_json_gen(fs, root_json, directory->version);
	assert_zero(root_json->error);

	if (fbr_cstore_backend_enabled(cstore)) {
		fail = fbr_cstore_s3_root_put(cstore, root_json, &root_path, &directory->etag,
			etag_match, FBR_CSTORE_ROUTE_CLUSTER);

		if (fbr_cstore_http_conflict(fail)) {
			fail = EAGAIN;
		} else if (fail) {
			fail = EIO;
		}
	} else {
		double now = fbr_get_time();
		fail = fbr_cstore_io_root_write(cstore, root_json, &root_path, &directory->etag,
			etag_match, now, NULL);
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
	int ret = fbr_cstore_io_index_delete(fs, directory);

	if (fbr_cstore_http_conflict(ret) || ret == EAGAIN) {
		return EAGAIN;
	} else if (ret) {
		return EIO;
	}

	return 0;
}

fbr_id_t
fbr_cstore_root_read(struct fbr_fs *fs, struct fbr_directory *directory, int route_s3)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	if (!fs->cstore) {
		return 0;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);

	struct fbr_cstore_path path;
	fbr_cstore_path_root(&dirpath, &path);

	fbr_id_t version = 0;
	int has_backend = fbr_cstore_backend_enabled(cstore);

	fbr_cstore_etag_init(&directory->etag, NULL);

	int http_error = 0;
	struct fbr_cstore_entry_ref _entry_ref;
	struct fbr_cstore_entry_ref *entry_ref = &_entry_ref;
	entry_ref->entry = NULL;

	if (!route_s3 || !has_backend) {
		version = fbr_cstore_io_root_read(cstore, &path, &directory->etag, 0, entry_ref);
	}

	if (!version && has_backend) {
		if (!entry_ref->entry) {
			fbr_cstore_etag_init(&directory->etag, NULL);
			entry_ref = NULL;
		}

		version = fbr_cstore_s3_root_get(fs, cstore, &path, &directory->etag, route_s3,
			entry_ref, &http_error, 0);

		if (!version && !route_s3 && http_error != 304) {
			version = fbr_cstore_s3_root_get(fs, cstore, &path, &directory->etag, 1,
				entry_ref, &http_error, 0);
		}
	}

	if (http_error == 304) {
		assert_zero(version);
		assert(entry_ref);
		assert(entry_ref->entry);

		fbr_cstore_io_root_touch(cstore, entry_ref, &path);

		version = entry_ref->version;
		assert(version);
	} else if (!route_s3 && has_backend && !version) {
		version = fbr_cstore_io_root_read(cstore, &path, &directory->etag, 1, entry_ref);
	}

	assert_zero(_entry_ref.entry);

	char id_str[FBR_ID_STRING_MAX] = "";
	if (version) {
		fbr_id_string(version, id_str, sizeof(id_str));
	}
	fbr_rlog(FBR_LOG_CS_ROOT, "READ %s version=%ld (%s) [%s]", path.value, version, id_str,
		directory->etag.value);

	return version;
}
