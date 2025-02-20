/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_path.h"

static size_t
_path_storage_len(size_t dirname_len, size_t filename_len)
{
	struct fbr_path *path;

	if (dirname_len <= sizeof(path->embed.data) && !filename_len) {
		return 0;
	} else if (!dirname_len && filename_len <= sizeof(path->embed.data)) {
		return 0;
	}

	return dirname_len + 1 + filename_len;
}

static void
_path_init(struct fbr_path *path, char *name_storage, const char *dirname,
    size_t dirname_len, const char *filename, size_t filename_len)
{
	assert(path);
	assert(path->layout.value == FBR_PATH_NULL);
	assert(dirname);
	assert(dirname_len <= FBR_PATH_PTR_LEN_MAX);
	assert(filename);
	assert(filename_len <= FBR_PATH_PTR_LEN_MAX);

	if (!_path_storage_len(dirname_len, filename_len)) {
		assert_zero(name_storage);
		name_storage = path->embed.data;

		if (!filename_len) {
			assert_dev(dirname_len <= FBR_PATH_EMBED_LEN_MAX);

			path->layout.value = FBR_PATH_EMBED_DIR;
			path->embed.len = dirname_len;
		} else {
			assert_zero(dirname_len);
			assert_dev(filename_len <= FBR_PATH_EMBED_LEN_MAX);

			path->layout.value = FBR_PATH_EMBED_FILE;
			path->embed.len = filename_len;
		}
	} else {
		assert(name_storage);

		path->layout.value = FBR_PATH_PTR;
		path->ptr.value = name_storage;
		path->ptr.dir_len = dirname_len;
		path->ptr.file_len = filename_len;
	}

	int extra_slash = 0;

	if (dirname_len) {
		memcpy(name_storage, dirname, dirname_len);

		if (filename_len) {
			name_storage[dirname_len] = '/';
			extra_slash = 1;
		}
	}

	if (filename_len) {
		memcpy(name_storage + dirname_len + extra_slash, filename, filename_len);
	}
}

void *
fbr_path_storage_alloc(size_t size, size_t path_offset, const char *dirname, size_t dirname_len,
    const char *filename, size_t filename_len)
{
	size_t storage_len = _path_storage_len(dirname_len, filename_len);
	char *storage_ptr = NULL;

	void *obj = calloc(1, size + storage_len);
	assert(obj);

	if (storage_len) {
		storage_ptr = (char*)obj + size;
	}

	struct fbr_path *path = (struct fbr_path*)((char*)obj + path_offset);

	_path_init(path, storage_ptr, dirname, dirname_len, filename, filename_len);

	return obj;
}

void
fbr_path_init_dir(struct fbr_path *path, const char *dirname, size_t dirname_len)
{
	assert(path);
	assert(dirname);

	fbr_ZERO(path);

	path->layout.value = FBR_PATH_PTR;
	path->ptr.dir_len = dirname_len;
	path->ptr.value = dirname;
}

void
fbr_path_init_file(struct fbr_path *path, const char *filename, size_t filename_len)
{
	assert(path);
	assert(filename);

	fbr_ZERO(path);

	path->layout.value = FBR_PATH_PTR;
	path->ptr.file_len = filename_len;
	path->ptr.value = filename;
}

void
fbr_path_get_dir(const struct fbr_path *path, struct fbr_path_name *result_dir)
{
	assert(path);
	assert(result_dir);

	fbr_ZERO(result_dir);

	if (path->layout.value == FBR_PATH_NULL) {
		return;
	} else if (path->layout.value == FBR_PATH_EMBED_DIR) {
		result_dir->len = path->embed.len;
		result_dir->name = path->embed.data;
		return;
	} else if (path->layout.value == FBR_PATH_EMBED_FILE) {
		result_dir->len = 0;
		result_dir->name = "";
		return;
	}

	assert(path->layout.value == FBR_PATH_PTR);

	result_dir->len = path->ptr.dir_len;
	result_dir->name = path->ptr.value;

	return;
}

void
fbr_path_get_file(const struct fbr_path *path, struct fbr_path_name *result_file)
{
	assert(path);
	assert(result_file);

	fbr_ZERO(result_file);

	if (path->layout.value == FBR_PATH_NULL) {
		return;
	} else if (path->layout.value == FBR_PATH_EMBED_DIR) {
		result_file->len = 0;
		result_file->name = "";
		return;
	} else if (path->layout.value == FBR_PATH_EMBED_FILE) {
		result_file->len = path->embed.len;
		result_file->name = path->embed.data;
		return;
	}

	assert(path->layout.value == FBR_PATH_PTR);

	int extra_slash = 0;
	if (path->ptr.dir_len && path->ptr.file_len) {
		extra_slash = 1;
	}

	result_file->len = path->ptr.file_len;
	result_file->name = path->ptr.value + path->ptr.dir_len + extra_slash;

	return;
}

void
fbr_path_get_full(const struct fbr_path *path, struct fbr_path_name *result)
{
	assert(path);
	assert(result);

	fbr_ZERO(result);

	if (path->layout.value == FBR_PATH_NULL) {
		return;
	} else if (path->layout.value == FBR_PATH_EMBED_DIR) {
		result->len = path->embed.len;
		result->name = path->embed.data;
		return;
	} else if (path->layout.value == FBR_PATH_EMBED_FILE) {
		result->len = 0;
		result->name = "";
		return;
	}

	assert(path->layout.value == FBR_PATH_PTR);

	int extra_slash = 0;
	if (path->ptr.dir_len && path->ptr.file_len) {
		extra_slash = 1;
	}

	result->len = path->ptr.dir_len + extra_slash + path->ptr.file_len;
	result->name = path->ptr.value;

	return;
}

int
fbr_path_cmp_dir(const struct fbr_path *dir1, const struct fbr_path *dir2)
{
	assert(dir1);
	assert(dir2);

	struct fbr_path_name dirname1, dirname2;
	fbr_path_get_dir(dir1, &dirname1);
	fbr_path_get_dir(dir2, &dirname2);

	int diff = dirname1.len - dirname2.len;

	if (diff) {
		return diff;
	}

	assert(dirname1.name && dirname2.name);

	return strncmp(dirname1.name, dirname2.name, dirname1.len);
}

int
fbr_path_cmp_file(const struct fbr_path *file1, const struct fbr_path *file2)
{
	assert(file1);
	assert(file2);

	struct fbr_path_name filename1, filename2;
	fbr_path_get_file(file1, &filename1);
	fbr_path_get_file(file2, &filename2);

	int diff = filename1.len - filename2.len;

	if (diff) {
		return diff;
	}

	assert(filename1.name && filename2.name);

	return strncmp(filename1.name, filename2.name, filename1.len);
}

void
fbr_path_free(struct fbr_path *path)
{
	assert(path);
	fbr_ZERO(path);
}
