/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fiberfs.h"
#include "compress/fbr_gzip.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_callback.h"
#include "utils/fbr_sys.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

static void
_index_hash_ok(struct fbr_cstore *cstore, fbr_hash_t hash)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	fbr_cstore_entry_ok(entry);
	assert(entry->state == FBR_CSTORE_OK);
	fbr_cstore_release(cstore, &entry);
	assert_zero(entry);
}

static size_t
_index_print_file(const char *path)
{
	assert(path);

	int fd = open(path, O_RDONLY);
	assert(fd >= 0);

	char buffer[4096];
	size_t total = 0;
	ssize_t bytes;

	while ((bytes = fbr_sys_read(fd, buffer, sizeof(buffer) - 1)) > 0) {
		assert(bytes > 0 && (size_t)bytes < sizeof(buffer));
		buffer[bytes] = '\0';
		fbr_test_logs("%s", buffer);
		total += bytes;
	}

	assert_zero(bytes);

	assert_zero(close(fd));

	return total;
}

static size_t
_index_print_file_gz(const char *path, size_t gz_bytes)
{
	assert(path);
	assert(gz_bytes);

	int fd = open(path, O_RDONLY);
	assert(fd >= 0);

	struct fbr_gzip gzip;
	fbr_gzip_inflate_init(&gzip);
	assert_dev(gzip.status == FBR_GZIP_DONE);

	char gz_buffer[4096];
	char out_buffer[4096];
	char *in_buffer;
	size_t in_len;
	size_t out_len;
	size_t total = 0;
	ssize_t bytes = 0;

	do {
		assert(gzip.status <= FBR_GZIP_DONE);
		if (gzip.status == FBR_GZIP_DONE) {
			bytes = fbr_sys_read(fd, gz_buffer, sizeof(gz_buffer));
			assert(bytes >= 0 && (size_t)bytes <= gz_bytes);

			if (!bytes) {
				break;
			}

			gz_bytes -= bytes;
		}

		in_buffer = gz_buffer;
		in_len = bytes;
		if (gzip.status == FBR_GZIP_MORE_BUFFER || !bytes) {
			in_buffer = NULL;
			in_len = 0;
		}

		fbr_gzip_flate(&gzip, in_buffer, in_len, out_buffer, sizeof(out_buffer) - 1,
			&out_len, 0);
		assert(gzip.status != FBR_GZIP_ERROR);
		assert(out_len < sizeof(out_buffer));

		out_buffer[out_len] = '\0';
		total += out_len;

		fbr_test_logs("%s", out_buffer);
	} while (bytes > 0);

	assert_zero(bytes);
	assert_zero(gz_bytes);
	assert(gzip.status == FBR_GZIP_DONE);

	fbr_gzip_free(&gzip);
	assert_zero(close(fd));

	return total;
}

static void
_index_metadata(struct fbr_cstore_hashpath *hashpath, struct fbr_cstore_metadata *metadata)
{
	assert(hashpath);
	assert(metadata);

	int ret = fbr_cstore_metadata_read(hashpath, metadata);
	assert_zero(ret);
	assert(ret == metadata->error);

	char etag[FBR_ID_STRING_MAX];
	fbr_id_string(metadata->etag, etag, sizeof(etag));

	fbr_test_logs(" *** hashpath: %s", hashpath->value);
	fbr_test_logs(" *** metadata.type: %s", fbr_cstore_type_name(metadata->type));
	fbr_test_logs(" *** metadata.path: '%s'", metadata->path);
	fbr_test_logs(" *** metadata.etag: '%s' (%lu)", etag, metadata->etag);
	fbr_test_logs(" *** metadata.size: %lu", metadata->size);
	fbr_test_logs(" *** metadata.offset: %lu", metadata->offset);
	fbr_test_logs(" *** metadata.timestamp: %lf", metadata->timestamp);
	fbr_test_logs(" *** metadata.gzip: %d", metadata->gzipped);
}

static void
_index_print_root(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	fbr_test_logs(" * ROOT");

	fbr_hash_t hash = fbr_cstore_hash_root(cstore, FBR_DIRNAME_ROOT);
	_index_hash_ok(cstore, hash);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);

	struct fbr_cstore_metadata metadata;
	_index_metadata(&hashpath, &metadata);
	assert(metadata.type == FBR_CSTORE_FILE_ROOT);
	assert_zero(metadata.gzipped);

	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	size_t size = _index_print_file(hashpath.value);
	assert(size == metadata.size);
}

static void
_index_print_index(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	fbr_test_logs(" * INDEX");

	fbr_hash_t hash = fbr_cstore_hash_index(cstore, directory);
	_index_hash_ok(cstore, hash);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);

	struct fbr_cstore_metadata metadata;
	_index_metadata(&hashpath, &metadata);
	assert(metadata.type == FBR_CSTORE_FILE_INDEX);

	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	if (metadata.gzipped) {
		size_t size = _index_print_file_gz(hashpath.value, metadata.size);
		fbr_test_logs(" *** bytes: %zu", size);
	} else {
		size_t size = _index_print_file(hashpath.value);
		assert(size == metadata.size);
	}
}

void
fbr_cmd_index_print_json(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_test_fs_mock(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_bind_new(fs);
	fbr_cstore_ok(fs->cstore);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);

	fbr_test_fs_root_alloc(fs);

	fbr_test_cstore_wait(fs->cstore);
	assert(fs->cstore->entries == 2);

	struct fbr_directory *root = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(root);

	_index_print_root(fs);
	_index_print_index(fs, root);

	fbr_dindex_release(fs, &root);

	fbr_test_logs("* Adding files to root");

	root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);
	fbr_directory_ok(root->previous);
	assert(root->previous->generation == 1);

	root->generation = root->previous->generation + 1;

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, "file_1");
	struct fbr_file *file = fbr_file_alloc(fs, root, &filename);
	file->generation = 1;
	file->size = 2048;
	file->mode = S_IFREG | 0444;
	file->uid = 1000;
	file->gid = 1000;
	fbr_body_chunk_add(fs, file, fbr_id_gen(), 0 , 1024);
	fbr_body_chunk_add(fs, file, fbr_id_gen(), 1024 , 1024);
	file->state = FBR_FILE_OK;

	fbr_path_name_init(&filename, "file_XYZ");
	file = fbr_file_alloc(fs, root, &filename);
	file->generation = 1;
	file->size = 200;
	file->mode = S_IFREG | 0444;
	file->uid = 1000;
	file->gid = 1000;
	fbr_body_chunk_add(fs, file, fbr_id_gen(), 0 , 150);
	fbr_body_chunk_add(fs, file, fbr_id_gen(), 150 , 50);
	file->state = FBR_FILE_OK;

	fbr_test_logs("* Writing root index");

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, root, root->previous, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	assert(root->state == FBR_DIRSTATE_LOADING);
	fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);

	fbr_test_cstore_wait(fs->cstore);
	assert(fs->cstore->entries == 2);

	_index_print_root(fs);
	_index_print_index(fs, root);

	fbr_dindex_release(fs, &root);

	fbr_fs_free(fs);

	fbr_test_logs("index_print_json done");
}
