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
#include "fjson.h"
#include "compress/fbr_gzip.h"
#include "core/fs/fbr_fs.h"
#include "core/request/fbr_request.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_callback.h"
#include "utils/fbr_sys.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
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

void
fbr_cmd_index_root_json_parse(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_fuse_mock(ctx);
	const char *root;
	fbr_id_t id;

	root = "{\"fiberfs\":1,\"v\":\"17773978380341182558\"}";
	id = fbr_root_json_parse(root, strlen(root));
	assert(id == 7633865586532288606);

	root = "{\"fiberfs\":9999999,\"v\":\"17773978380341182558\"}";
	id = fbr_root_json_parse(root, strlen(root));
	assert_zero(id);

	root = "{\"v\":\"17773978380341182558\"}";
	id = fbr_root_json_parse(root, strlen(root));
	assert_zero(id);

	root = "{\"fiberfs\":3,\"v\":\"1234567890\",\"zzz\":63}";
	id = fbr_root_json_parse(root, strlen(root));
	assert(id == 1234567890);

	root = "{\"fiberfs\":1,\"aaa\":{\"bbb\":\"222\"},"
		"\"v\":\"0\",\"v\":\"11234567890\",\"V\":\"end\"}";
	id = fbr_root_json_parse(root, strlen(root));
	fbr_ASSERT(id == 5529535186, "id: %lu", id);

	root = "{\"fiberfs\":3,\"v\":\"17774010392543342732\",\"v\":{\"v\":\"123\"}}";
	id = fbr_root_json_parse(root, strlen(root));
	assert(id == 7633879336924763276);

	root = "{\"fiberfs\":1,\"v\":\"17773978380341182558}";
	id = fbr_root_json_parse(root, strlen(root));
	assert_zero(id);

	root = "{\"fiberfs\":1}";
	id = fbr_root_json_parse(root, strlen(root));
	assert_zero(id);

	root = "{}";
	id = fbr_root_json_parse(root, strlen(root));
	assert_zero(id);

	root = "xyz";
	id = fbr_root_json_parse(root, strlen(root));
	assert_zero(id);

	root = "\"123\"";
	id = fbr_root_json_parse(root, strlen(root));
	assert_zero(id);

	fbr_test_logs("index_root_json_parse done");
}

static struct fbr_directory *
_parse_directory(struct fbr_fs *fs, const char *index_json)
{
	fbr_fs_ok(fs);
	assert(index_json);

	struct fbr_request *request = fbr_test_request_mock();

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	assert_zero(directory->generation);

	struct fbr_index_parser parser;
	struct fjson_context json;
	fbr_index_parser_init(fs, &parser, directory, &json);
	assert(json.callback);
	assert(json.callback_priv == &parser);

	fjson_parse(&json, index_json, strlen(index_json));

	int ret = fbr_index_parser_validate(&parser);

	if (ret) {
		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_ERROR);
	} else {
		assert(directory->generation);
		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	}

	fbr_index_parser_free(&parser);

	fbr_request_free(request);

	return directory;
}

void
fbr_cmd_index_json_parse(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_fuse_mock(ctx);

	struct fbr_fs *fs = fbr_test_fs_mock(ctx);
	fbr_fs_ok(fs);

	const char *json = "{\"fiberfs\":1,\"g\":1,\"f\":[]}";
	struct fbr_directory *directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(directory->generation == 1);
	fbr_dindex_release(fs, &directory);

	json = "{\"fiberfs\":9999999,\"g\":1,\"f\":[]}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &directory);

	json = "{\"g\":1,\"f\":[]}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &directory);

	json = "{\"z\":1}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &directory);

	json = "{}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &directory);

	json = "123";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &directory);

	json = "zzz";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &directory);

	json = "{\"fiberfs\":3,\"f\":[]}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &directory);

	json = "{\"fiberfs\":1,\"f\":[],\"g\":3}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(directory->generation == 3);
	fbr_dindex_release(fs, &directory);

	json = "{\"fiberfs\":6,\"g\":665}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(directory->generation == 665);
	fbr_dindex_release(fs, &directory);

	json = "{\"fiberfs\":6,\"g\":663}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &directory);

	json = "{\"fiberfs\":6,\"g\":665}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &directory);

	fbr_fs_release_all(fs, 0);
	fbr_test_fs_wait(fs);

	json = "{\"fiberfs\":1,\"g\":1,\"f\":[{\"n\":\"file_1\",\"j\":1,\"s\":2048,\"m\":33060,"
		"\"u\":1000,\"p\":1000,\"b\":[{\"i\":\"17775679553136982062\",\"o\":0,\"l\":1024},"
		"{\"i\":\"17775679550948149444\",\"o\":1024,\"l\":1024}]},{\"n\":\"file_XYZ\","
		"\"j\":1,\"s\":200,\"m\":33060,\"u\":1000,\"p\":1000,\"b\":[{\"i\":"
		"\"17775679552912043528\",\"o\":0,\"l\":150},{\"i\":\"17775679552326286274\","
		"\"o\":150,\"l\":50}]}]}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert_zero(directory->previous);
	assert(directory->generation == 1);
	assert(directory->file_count == 2);
	struct fbr_file *file = fbr_directory_find_file(directory, "file_1", 6);
	fbr_file_ok(file);
	assert(fbr_test_fs_count_chunks(file) == 2);
	assert(fbr_test_fs_get_chunk(file, 0)->offset == 0);
	assert(fbr_test_fs_get_chunk(file, 0)->length == 1024);
	assert(fbr_test_fs_get_chunk(file, 1)->offset == 1024);
	assert(fbr_test_fs_get_chunk(file, 1)->length == 1024);
	assert(file->size == 2048);
	file = fbr_directory_find_file(directory, "file_XYZ", 8);
	fbr_file_ok(file);
	assert(fbr_test_fs_count_chunks(file) == 2);
	assert(fbr_test_fs_get_chunk(file, 0)->offset == 0);
	assert(fbr_test_fs_get_chunk(file, 0)->length == 150);
	assert(fbr_test_fs_get_chunk(file, 1)->offset == 150);
	assert(fbr_test_fs_get_chunk(file, 1)->length == 50);
	assert(file->size == 200);
	fbr_dindex_release(fs, &directory);

	// 1 new file, 1 unchanged/inherited
	json = "{\"fiberfs\":1,\"g\":2,\"f\":[{\"n\":\"file_ABC\",\"j\":1},"
		"{\"n\":\"file_XYZ\",\"j\":1}]}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(directory->generation == 2);
	assert(directory->file_count == 2);
	file = fbr_directory_find_file(directory, "file_ABC", 8);
	fbr_file_ok(file);
	assert_zero(fbr_test_fs_count_chunks(file));
	file = fbr_directory_find_file(directory, "file_XYZ", 8);
	fbr_file_ok(file);
	assert(fbr_test_fs_count_chunks(file) == 2);
	fbr_dindex_release(fs, &directory);

	// 1 unchanged, 1 dropped/inherited (no gen)
	json = "{\"fiberfs\":1,\"g\":3,\"f\":[{\"n\":\"file_ABC\",\"j\":1},"
		"{\"n\":\"file_XYZ\"}]}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(directory->generation == 3);
	assert(directory->file_count == 2);
	file = fbr_directory_find_file(directory, "file_ABC", 8);
	fbr_file_ok(file);
	assert_zero(fbr_test_fs_count_chunks(file));
	file = fbr_directory_find_file(directory, "file_XYZ", 8);
	fbr_file_ok(file);
	assert(fbr_test_fs_count_chunks(file) == 2);
	fbr_dindex_release(fs, &directory);

	// 1 other new file, 1 unchanged/inherited
	json = "{\"fiberfs\":1,\"g\":4,\"f\":[{\"n\":\"file_ABC\",\"j\":1},"
		"{\"n\":\"file_XYZ\",\"j\":2}]}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(directory->generation == 4);
	assert(directory->file_count == 2);
	file = fbr_directory_find_file(directory, "file_ABC", 8);
	fbr_file_ok(file);
	assert(file->generation == 1);
	assert_zero(fbr_test_fs_count_chunks(file));
	file = fbr_directory_find_file(directory, "file_XYZ", 8);
	fbr_file_ok(file);
	assert(file->generation == 2);
	assert_zero(fbr_test_fs_count_chunks(file));
	fbr_dindex_release(fs, &directory);

	// 1 dropped, 1 unchanged/inherited
	json = "{\"fiberfs\":1,\"g\":5,\"f\":[{\"n\":\"file_ABC\",\"j\":1}]}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(directory->generation == 5);
	assert(directory->file_count == 1);
	file = fbr_directory_find_file(directory, "file_ABC", 8);
	fbr_file_ok(file);
	assert(file->generation == 1);
	assert_zero(fbr_test_fs_count_chunks(file));
	fbr_dindex_release(fs, &directory);

	// duplicate filename (merged)
	json = "{\"fiberfs\":1,\"g\":6,\"f\":[{\"n\":\"file_ABC\",\"j\":1},"
		"{\"n\":\"file_ABC\",\"j\":2}]}";
	directory = _parse_directory(fs, json);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(directory->generation == 6);
	assert(directory->file_count == 1);
	file = fbr_directory_find_file(directory, "file_ABC", 8);
	fbr_file_ok(file);
	assert(file->generation == 2);
	assert_zero(fbr_test_fs_count_chunks(file));
	fbr_dindex_release(fs, &directory);

	fbr_fs_release_all(fs, 1);
	fbr_test_fs_stats(fs);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");

	fbr_request_pool_shutdown();
	fbr_fs_free(fs);

	fbr_test_logs("index_json_parse done");
}
