/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "data/tree.h"
#include "fbr_store.h"

static void
_json_header(struct fbr_fs *fs, struct fbr_writer *json)
{
	assert_dev(fs);
	assert_dev(json);

	// fiberfs: version header
	fbr_writer_add(fs, json,
		"{\"" FBR_JSON_HEADER "\":" FBR_STRINGIFY(FBR_JSON_VERSION) ",",
		2 + (sizeof(FBR_JSON_HEADER) - 1) + 2 +
			(sizeof(FBR_STRINGIFY(FBR_JSON_VERSION)) - 1) + 1);
}

static void
_json_footer(struct fbr_fs *fs, struct fbr_writer *json)
{
	assert_dev(fs);
	assert_dev(json);

	fbr_writer_add(fs, json, "}", 1);
}

static void
_json_body(struct fbr_fs *fs, struct fbr_writer *json, struct fbr_body *body)
{
	assert_dev(fs);
	assert_dev(json);
	assert_dev(body);

	// b: body chunks
	fbr_writer_add(fs, json, ",\"b\":[", 6);

	struct fbr_chunk *chunk = body->chunks;

	while (chunk) {
		fbr_chunk_ok(chunk);
		assert_dev(chunk->state >= FBR_CHUNK_EMPTY);

		// i: chunk id (string)
		fbr_writer_add(fs, json, "{\"i\":\"", 6);
		fbr_writer_add_id(fs, json, chunk->id);

		// o: chunk offset
		fbr_writer_add(fs, json, "\",\"o\":", 6);
		fbr_writer_add_ulong(fs, json, chunk->offset);

		chunk = chunk->next;

		if (chunk) {
			fbr_writer_add(fs, json, "},", 2);
		} else {
			fbr_writer_add(fs, json, "}", 1);
		}
	}

	fbr_writer_add(fs, json, "]", 1);
}

static void
_json_file(struct fbr_fs *fs, struct fbr_writer *json, struct fbr_file *file)
{
	assert_dev(fs);
	assert_dev(json);
	assert_dev(file);

	// n: filename
	fbr_writer_add(fs, json, "{\"n\":\"", 6);

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	fbr_writer_add(fs, json, filename.name, filename.len);

	// j: file generation
	fbr_writer_add(fs, json, "\",\"j\":", 6);
	fbr_writer_add_ulong(fs, json, file->generation);

	// s: file size
	fbr_writer_add(fs, json, ",\"s\":", 5);
	fbr_writer_add_ulong(fs, json, file->size);

	// m: file mode
	fbr_writer_add(fs, json, ",\"m\":", 5);
	fbr_writer_add_ulong(fs, json, file->mode);

	_json_body(fs, json, &file->body);

	fbr_writer_add(fs, json, "}", 1);
}

static void
_json_directory(struct fbr_fs *fs, struct fbr_writer *json, struct fbr_directory *directory)
{
	assert_dev(fs);
	assert_dev(json);

	// g: generation
	fbr_writer_add(fs, json, "\"g\":", 4);
	fbr_writer_add_ulong(fs, json, directory->generation);

	// f: files array
	fbr_writer_add(fs, json, ",\"f\":[", 6);

	struct fbr_file_ptr *file_ptr;
	int comma = 0;
	RB_FOREACH(file_ptr, fbr_filename_tree, &directory->filename_tree) {
		fbr_file_ptr_ok(file_ptr);
		struct fbr_file *file = file_ptr->file;

		if (comma) {
			fbr_writer_add(fs, json, ",", 1);
		}

		_json_file(fs, json, file);

		comma = 1;
	}

	fbr_writer_add(fs, json, "]", 1);
}

int
fbr_store_index(struct fbr_fs *fs, struct fbr_directory *directory, struct fbr_directory *previous)
{
	fbr_fs_ok(fs);
	assert_dev(fs->store);
	fbr_directory_ok(directory);
	assert_dev(directory->version);

	struct fbr_request *request = fbr_request_get();

	struct fbr_writer json;
	fbr_writer_init(fs, request, &json, 1);

	_json_header(fs, &json);
	_json_directory(fs, &json, directory);
	_json_footer(fs, &json);

	fbr_writer_add(fs, &json, NULL, 0);

	fbr_writer_debug(fs, &json);

	int ret = EIO;

	if (fs->store->store_index_f) {
		ret = fs->store->store_index_f(fs, directory, &json, previous);
	}

	fbr_writer_free(fs, &json);

	return ret;
}

size_t
fbr_root_json(fbr_id_t version, char *buffer, size_t buffer_len)
{
	assert(buffer);
	assert(buffer_len >= 50);

	char version_str[FBR_ID_STRING_MAX];
	fbr_id_string(version, version_str, sizeof(version_str));

	// fiberfs: version header
	// v: index version
	int ret = snprintf(buffer, buffer_len, "{\"%s\":%s,\"v\":\"%s\"}",
		FBR_JSON_HEADER,
		FBR_STRINGIFY(FBR_JSON_VERSION),
		version_str);
	assert(ret > 0 && (size_t)ret < buffer_len);

	return (size_t)ret;
}
