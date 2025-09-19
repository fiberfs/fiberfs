/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_path.h"

static size_t
_path_storage_len(const struct fbr_path_shared *dirname, const struct fbr_path_name *filename)
{
	assert(dirname);
	assert(filename);

	struct fbr_path *path;

	if (dirname->value.length < sizeof(path->embed.data) && !filename->length) {
		return 0;
	} else if (!dirname->value.length && filename->length < sizeof(path->embed.data)) {
		return 0;
	}

	int null = 1;
	return filename->length + null;
}

static void
_path_init(struct fbr_path *path, char *name_storage, struct fbr_path_shared *dirname,
	const struct fbr_path_name *filename)
{
	assert_dev(path);
	assert(path->layout.value == FBR_PATH_NULL);
	assert(dirname && dirname->value.name);
	assert(dirname->value.length <= FBR_PATH_PTR_LEN_MAX);
	assert(filename && filename->name);
	assert(filename->length <= FBR_PATH_PTR_LEN_MAX);

	if (!_path_storage_len(dirname, filename)) {
		assert_zero(name_storage);
		name_storage = path->embed.data;

		if (!filename->length) {
			assert_dev(dirname->value.length <= FBR_PATH_EMBED_LEN_MAX);

			path->layout.value = FBR_PATH_EMBED_DIR;
			path->embed.len = dirname->value.length;

			memcpy(name_storage, dirname->value.name, dirname->value.length);

			assert_dev(name_storage[dirname->value.length] == '\0');
		} else {
			assert_zero(dirname->value.length);
			assert_dev(filename->length <= FBR_PATH_EMBED_LEN_MAX);

			path->layout.value = FBR_PATH_EMBED_FILE;
			path->embed.len = filename->length;

			memcpy(name_storage, filename->name, filename->length);

			assert_dev(name_storage[filename->length] == '\0');
		}
	} else {
		assert(name_storage);
		assert(name_storage > (char*)path);
		assert(name_storage - (char*)path <= FBR_PATH_PTR_OFFSET_MAX);

		path->layout.value = FBR_PATH_SPLIT_PTR;
		path->split_ptr.file_len = filename->length;
		path->split_ptr.file_offset = name_storage - (char*)path;
		path->split_ptr.dirname = fbr_path_shared_take(dirname);

		memcpy(name_storage, filename->name, filename->length);

		assert_dev(name_storage[filename->length] == '\0');
	}
}

static const char *
_path_split_file(const struct fbr_path *path)
{
	assert(path);
	assert(path->layout.value == FBR_PATH_SPLIT_PTR);
	assert_dev(path->split_ptr.file_offset);

	char *filename = (char*)path + path->split_ptr.file_offset;

	assert_dev(strlen(filename) == path->split_ptr.file_len);

	return filename;
}

void *
fbr_path_storage_alloc(size_t size, size_t path_offset, struct fbr_path_shared *dirname,
    const struct fbr_path_name *filename)
{
	fbr_path_shared_ok(dirname);
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

	path->layout.value = FBR_PATH_DIR_PTR;
	path->ptr.value_len = dirname_len;
	path->ptr.value = dirname;
}


void
fbr_path_init_file(struct fbr_path *path, const char *filename, size_t filename_len)
{
	assert(path);
	assert(filename);

	fbr_ZERO(path);

	path->layout.value = FBR_PATH_FILE_PTR;
	path->ptr.value_len = filename_len;
	path->ptr.value = filename;
}

void
fbr_path_get_dir(const struct fbr_path *path, struct fbr_path_name *result_dir)
{
	assert(path);
	assert(result_dir);

	fbr_ZERO(result_dir);

	switch (path->layout.value) {
		case FBR_PATH_NULL:
			return;
		case FBR_PATH_EMBED_DIR:
			result_dir->length = path->embed.len;
			result_dir->name = path->embed.data;
			return;
		case FBR_PATH_EMBED_FILE:
			result_dir->length = 0;
			result_dir->name = "";
			return;
		case FBR_PATH_FILE_PTR:
			result_dir->length = 0;
			result_dir->name = "";
			return;
		case FBR_PATH_DIR_PTR:
			result_dir->length = path->ptr.value_len;
			result_dir->name = path->ptr.value;
			return;
		case FBR_PATH_SPLIT_PTR:
			fbr_path_shared_name(path->split_ptr.dirname, result_dir);
			return;
	}

	fbr_ABORT("bad path layout: %d", path->layout.value);
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

	switch (path->layout.value) {
		case FBR_PATH_NULL:
			return NULL;
		case FBR_PATH_EMBED_DIR:
			result_file->length = 0;
			result_file->name = "";
			return result_file->name;
		case FBR_PATH_EMBED_FILE:
			result_file->length = path->embed.len;
			result_file->name = path->embed.data;
			return result_file->name;
		case FBR_PATH_FILE_PTR:
			result_file->length = path->ptr.value_len;
			result_file->name = path->ptr.value;
			return result_file->name;
		case FBR_PATH_DIR_PTR:
			result_file->length = 0;
			result_file->name = "";
			return result_file->name;
		case FBR_PATH_SPLIT_PTR:
			result_file->length = path->split_ptr.file_len;
			result_file->name = _path_split_file(path);
			return result_file->name;
	}

	fbr_ABORT("bad path layout: %d", path->layout.value);
}

const char *
fbr_path_get_full(const struct fbr_path *path, struct fbr_path_name *result, char *buf,
    size_t buf_len)
{
	assert(path);

	struct fbr_path_name _result;
	if (!result) {
		result = &_result;
	}

	fbr_ZERO(result);

	switch (path->layout.value) {
		case FBR_PATH_NULL:
			return NULL;
		case FBR_PATH_EMBED_DIR:
			result->length = path->embed.len;
			result->name = path->embed.data;
			return result->name;
		case FBR_PATH_EMBED_FILE:
			result->length = path->embed.len;
			result->name = path->embed.data;
			return result->name;
		case FBR_PATH_FILE_PTR:
		case FBR_PATH_DIR_PTR:
			result->length = path->ptr.value_len;
			result->name = path->ptr.value;
			return result->name;
	}

	fbr_ASSERT(path->layout.value == FBR_PATH_SPLIT_PTR, "bad path layout: %d",
		path->layout.value);
	assert(buf);
	assert(buf_len);

	struct fbr_path_name dirname;
	fbr_path_shared_name(path->split_ptr.dirname, &dirname);

	size_t len = 0;
	buf[0] = '\0';

	if (dirname.length) {
		assert_dev(dirname.name);

		strncat(buf, dirname.name, buf_len - len - 1);
		len += dirname.length;
		assert(len < buf_len - 1);

		if (path->split_ptr.file_len) {
			strncat(buf, "/", buf_len - len - 1);
			len++;
			assert(len < buf_len - 1);
		}

	}

	if (path->split_ptr.file_len)
	{
		const char *filename = _path_split_file(path);

		strncat(buf, filename, buf_len - len - 1);
		len += path->split_ptr.file_len;
		assert(len < buf_len - 1);
	}

	assert_dev(buf[len] == '\0');

	result->length = len;
	result->name = buf;

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

	if (dirname1.length > dirname2.length) {
		return 1;
	} else if (dirname1.length < dirname2.length) {
		return -1;
	}

	assert(dirname1.name && dirname2.name);

	return strncmp(dirname1.name, dirname2.name, dirname1.length);
}

int
fbr_path_cmp_file(const struct fbr_path *file1, const struct fbr_path *file2)
{
	assert(file1);
	assert(file2);

	struct fbr_path_name filename1, filename2;
	fbr_path_get_file(file1, &filename1);
	fbr_path_get_file(file2, &filename2);

	if (filename1.length > filename2.length) {
		return 1;
	} else if (filename1.length < filename2.length) {
		return -1;
	}

	assert(filename1.name && filename2.name);

	return strncmp(filename1.name, filename2.name, filename1.length);
}

struct fbr_path_name *
fbr_path_name_init(struct fbr_path_name *name, const char *str)
{
	assert(name);
	assert(str);

	name->length = strlen(str);
	name->name = str;

	return name;
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

	if (name1->length > name2->length) {
		return 1;
	} else if (name1->length < name2->length) {
		return -1;
	}

	assert(name1->name && name2->name);

	return strncmp(name1->name, name2->name, name1->length);
}

void
fbr_path_name_parent(const struct fbr_path_name *name, struct fbr_path_name *result)
{
	assert(name);
	assert(result);

	if (result != name) {
		memcpy(result, name, sizeof(*result));
	}

	while (result->length > 0) {
		if (result->name[result->length - 1] == '/') {
			result->length--;
			break;
		}

		result->length--;
	}
}

void
fbr_path_free(struct fbr_path *path)
{
	assert(path);

	if (path->layout.value == FBR_PATH_SPLIT_PTR) {
		fbr_path_shared_release(path->split_ptr.dirname);
	}

	fbr_ZERO(path);
}

void
fbr_path_shared_init(struct fbr_path_shared *shared, const struct fbr_path_name *value)
{
	assert(shared);
	assert(value);
	assert(value->name);

	shared->magic = FBR_PATH_SHARED_MAGIC;
	shared->refcount = 0;

	fbr_path_name_init(&shared->value, value->name);

	assert_dev(strlen(shared->value.name) == shared->value.length);

	fbr_path_shared_ok(shared);
}

struct fbr_path_shared *
fbr_path_shared_alloc(const struct fbr_path_name *value)
{
	assert(value);

	struct fbr_path_shared *shared = malloc(sizeof(*shared));
	assert(shared);

	struct fbr_path_name value_dup;
	fbr_path_name_init(&value_dup, strdup(value->name));

	fbr_path_shared_init(shared, &value_dup);

	shared->refcount = 1;

	return shared;
}

struct fbr_path_shared *
fbr_path_shared_take(struct fbr_path_shared *shared)
{
	fbr_path_shared_ok(shared);
	assert(shared->refcount);

	fbr_refcount_t refs = fbr_atomic_add(&shared->refcount, 1);
	assert(refs > 1);

	return shared;
}

int
fbr_path_shared_cmp(const struct fbr_path_shared *shared1, const struct fbr_path_shared *shared2)
{
	fbr_path_shared_ok(shared1);
	fbr_path_shared_ok(shared2);

	return fbr_path_name_cmp(&shared1->value, &shared2->value);
}

void
fbr_path_shared_name(struct fbr_path_shared *shared, struct fbr_path_name *result)
{
	fbr_path_shared_ok(shared);
	assert(result);

	result->length = shared->value.length;
	result->name = shared->value.name;
}

void
fbr_path_shared_release(struct fbr_path_shared *shared)
{
	fbr_path_shared_ok(shared);
	assert(shared->refcount);

	fbr_refcount_t refs = fbr_atomic_sub(&shared->refcount, 1);

	if (refs) {
		return;
	}

	assert_dev(shared->value.name);
	free((char*)shared->value.name);

	fbr_ZERO(shared);
	free(shared);
}
