/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_fs.h"

void
fbr_alias_path_alloc(struct fbr_fs *fs, struct fbr_file *file, const struct fbr_path_name *value)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert_zero(file->alias_path);
	assert(value);

	file->alias_path = fbr_path_shared_alloc(value);
}

void
fbr_alias_path_take(struct fbr_fs *fs, struct fbr_file *source, struct fbr_file *dest)
{
	fbr_fs_ok(fs);
	fbr_file_ok(source);
	assert(source->alias_path);
	fbr_file_ok(dest);
	assert_zero(dest->alias_path);

	dest->alias_path = fbr_path_shared_take(source->alias_path);
}

void
fbr_alias_path_free(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(file->alias_path);

	fbr_path_shared_release(file->alias_path);

	file->alias_path = NULL;
}

int
fbr_alias_path_cmp(struct fbr_file *file1, struct fbr_file *file2)
{
	fbr_file_ok(file1);
	fbr_file_ok(file2);

	if (!file1->alias_path && !file2->alias_path) {
		return 0;
	}

	if (file1->alias_path && file2->alias_path) {
		fbr_path_shared_ok(file1->alias_path);
		fbr_path_shared_ok(file2->alias_path);

		return fbr_path_name_cmp(&file1->alias_path->value, &file2->alias_path->value);
	}

	if (!file1->alias_path) {
		assert_dev(file2->alias_path);
		return -1;
	}

	assert_dev(!file2->alias_path);

	return 1;
}
