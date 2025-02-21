/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_path.h"

static const struct fbr_path_name _PATH_NAME_EMPTY = {0, ""};
const struct fbr_path_name *PATH_NAME_EMPTY = &_PATH_NAME_EMPTY;

static size_t
_path_storage_len(const struct fbr_path_name *dirname, const struct fbr_path_name *filename)
{
	assert(dirname);
	assert(filename);

	struct fbr_path *path;

	if (dirname->len < sizeof(path->embed.data) && !filename->len) {
		return 0;
	} else if (!dirname->len && filename->len < sizeof(path->embed.data)) {
		return 0;
	}

	return dirname->len + 1 + filename->len + 1;
}

static void
_path_init(struct fbr_path *path, char *name_storage, const struct fbr_path_name *dirname,
	const struct fbr_path_name *filename)
{
	assert(path);
	assert(path->layout.value == FBR_PATH_NULL);
	assert(dirname && dirname->name);
	assert(dirname->len <= FBR_PATH_PTR_LEN_MAX);
	assert(filename && filename->name);
	assert(filename->len <= FBR_PATH_PTR_LEN_MAX);

	if (!_path_storage_len(dirname, filename)) {
		assert_zero(name_storage);
		name_storage = path->embed.data;

		if (!filename->len) {
			assert_dev(dirname->len <= FBR_PATH_EMBED_LEN_MAX);

			path->layout.value = FBR_PATH_EMBED_DIR;
			path->embed.len = dirname->len;
		} else {
			assert_zero(dirname->len);
			assert_dev(filename->len <= FBR_PATH_EMBED_LEN_MAX);

			path->layout.value = FBR_PATH_EMBED_FILE;
			path->embed.len = filename->len;
		}
	} else {
		assert(name_storage);

		path->layout.value = FBR_PATH_PTR;
		path->ptr.value = name_storage;
		path->ptr.dir_len = dirname->len;
		path->ptr.file_len = filename->len;
	}

	int extra_slash = 0;

	if (dirname->len) {
		memcpy(name_storage, dirname->name, dirname->len);

		if (filename->len) {
			name_storage[dirname->len] = '/';
			extra_slash = 1;
		}
	}

	if (filename->len) {
		memcpy(name_storage + dirname->len + extra_slash, filename->name, filename->len);
	}

	assert_dev(name_storage[dirname->len + extra_slash + filename->len] == 0);
}

void *
fbr_path_storage_alloc(size_t size, size_t path_offset, const struct fbr_path_name *dirname,
    const struct fbr_path_name *filename)
{
	assert(dirname);
	assert(filename);

	size_t storage_len = _path_storage_len(dirname, filename);
	char *storage_ptr = NULL;

	void *obj = calloc(1, size + storage_len);
	assert(obj);

	if (storage_len) {
		storage_ptr = (char*)obj + size;
	}

	struct fbr_path *path = (struct fbr_path*)((char*)obj + path_offset);

	_path_init(path, storage_ptr, dirname, filename);

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

const char *
fbr_path_get_file(const struct fbr_path *path, struct fbr_path_name *result_file)
{
	assert(path);

	struct fbr_path_name _result;
	if (!result_file) {
		result_file = &_result;
	}

	fbr_ZERO(result_file);

	if (path->layout.value == FBR_PATH_NULL) {
		return NULL;
	} else if (path->layout.value == FBR_PATH_EMBED_DIR) {
		result_file->len = 0;
		result_file->name = "";
		return result_file->name ;
	} else if (path->layout.value == FBR_PATH_EMBED_FILE) {
		result_file->len = path->embed.len;
		result_file->name = path->embed.data;
		return result_file->name ;
	}

	assert(path->layout.value == FBR_PATH_PTR);

	int extra_slash = 0;
	if (path->ptr.dir_len && path->ptr.file_len) {
		extra_slash = 1;
	}

	result_file->len = path->ptr.file_len;
	result_file->name = path->ptr.value + path->ptr.dir_len + extra_slash;

	return result_file->name;
}

const char *
fbr_path_get_full(const struct fbr_path *path, struct fbr_path_name *result)
{
	assert(path);

	struct fbr_path_name _result;
	if (!result) {
		result = &_result;
	}

	fbr_ZERO(result);

	if (path->layout.value == FBR_PATH_NULL) {
		return NULL;
	} else if (path->layout.value == FBR_PATH_EMBED_DIR) {
		result->len = path->embed.len;
		result->name = path->embed.data;
		return result->name;
	} else if (path->layout.value == FBR_PATH_EMBED_FILE) {
		result->len = path->embed.len;
		result->name = path->embed.data;
		return result->name;
	}

	assert(path->layout.value == FBR_PATH_PTR);

	int extra_slash = 0;
	if (path->ptr.dir_len && path->ptr.file_len) {
		extra_slash = 1;
	}

	result->len = path->ptr.dir_len + extra_slash + path->ptr.file_len;
	result->name = path->ptr.value;

	return result->name;
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
fbr_path_name_init(struct fbr_path_name *name, const char *str)
{
	assert(name);
	assert(str);

	name->len = strlen(str);
	name->name = str;
}

int
fbr_path_name_str_cmp(const struct fbr_path_name *name, const char *str)
{
	assert(name);
	assert(str);

	struct fbr_path_name name_str;
	fbr_path_name_init(&name_str, str);

	return fbr_path_name_cmp(name, &name_str);
}

int
fbr_path_name_cmp(const struct fbr_path_name *name1, const struct fbr_path_name *name2)
{
	assert(name1);
	assert(name2);

	int diff = name1->len - name2->len;

	if (diff) {
		return diff;
	}

	return strncmp(name1->name, name2->name, name1->len);
}

void
fbr_path_name_parent(const struct fbr_path_name *name, struct fbr_path_name *result)
{
	assert(name);
	assert(result);

	if (result != name) {
		memcpy(result, name, sizeof(*result));
	}

	while (result->len > 0) {
		if (result->name[result->len - 1] == '/') {
			result->len--;
			break;
		}

		result->len--;
	}
}

void
fbr_path_free(struct fbr_path *path)
{
	assert(path);
	fbr_ZERO(path);
}
