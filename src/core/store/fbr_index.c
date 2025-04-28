/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "data/tree.h"
#include "fbr_store.h"

static void
_json_header(struct fbr_fs *fs, struct fbr_writer *json)
{
	assert_dev(fs);
	assert_dev(json);

	fbr_writer_add(fs, json, "{\"", 2);
	fbr_writer_add(fs, json, FBR_JSON_HEADER, sizeof(FBR_JSON_HEADER) - 1);
	fbr_writer_add(fs, json, "\":", 2);
	fbr_writer_add(fs, json, FBR_STRINGIFY(FBR_JSON_VERSION),
		sizeof(FBR_STRINGIFY(FBR_JSON_VERSION)) - 1);
	fbr_writer_add(fs, json, ",", 1);
}

static void
_json_footer(struct fbr_fs *fs, struct fbr_writer *json)
{
	assert_dev(fs);
	assert_dev(json);

	fbr_writer_add(fs, json, "}", 1);
}

static void
_json_file(struct fbr_fs *fs, struct fbr_writer *json, struct fbr_file *file)
{
	assert_dev(fs);
	assert_dev(json);
	assert_dev(file);

	fbr_writer_add(fs, json, "{\"n\":\"", 6);

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	fbr_writer_add(fs, json, filename.name, filename.len);

	fbr_writer_add(fs, json, "\"}", 2);
}

static void
_json_directory(struct fbr_fs *fs, struct fbr_writer *json, struct fbr_directory *directory)
{
	assert_dev(fs);
	assert_dev(json);

	fbr_writer_add(fs, json, "\"g\":", 4);
	fbr_writer_add_ulong(fs, json, directory->generation);
	fbr_writer_add(fs, json, ",\"f\":[", 6);

	struct fbr_file_ptr *file_ptr;
	RB_FOREACH(file_ptr, fbr_filename_tree, &directory->filename_tree) {
		fbr_file_ptr_ok(file_ptr);
		struct fbr_file *file = file_ptr->file;
		_json_file(fs, json, file);
	}

	fbr_writer_add(fs, json, "]", 1);
}

int
fbr_store_index(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_writer json;
	fbr_writer_init(fs, &json, 1);

	_json_header(fs, &json);
	_json_directory(fs, &json, directory);
	_json_footer(fs, &json);

	fbr_writer_add(fs, &json, NULL, 0);

	fbr_writer_debug(fs, &json);
	fs->log("ZZZ '%.*s':%zu", (int)json.final->buffer_pos, json.final->buffer,
		json.final->buffer_pos);

	fbr_writer_free(fs, &json);

	return 1;
}
