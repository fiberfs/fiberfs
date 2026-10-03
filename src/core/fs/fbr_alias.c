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
	assert_zero(fbr_has_alias_path(file));
	assert(value);

	file->alias.path = fbr_path_shared_alloc(value);
}

void
fbr_alias_path_take(struct fbr_fs *fs, struct fbr_file *source, struct fbr_file *dest)
{
	fbr_fs_ok(fs);
	fbr_file_ok(source);
	assert(fbr_has_alias_path(source));
	fbr_file_ok(dest);
	assert_zero(fbr_has_alias_path(dest));

	dest->alias.path = fbr_path_shared_take(source->alias.path);
}

void
fbr_alias_path_free(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(fbr_has_alias_path(file));

	fbr_path_shared_release(file->alias.path);

	file->alias.path = NULL;
}

int
fbr_alias_path_cmp(struct fbr_file *file1, struct fbr_file *file2)
{
	fbr_file_ok(file1);
	fbr_file_ok(file2);

	if (!fbr_has_alias_path(file1) && !fbr_has_alias_path(file2)) {
		return 0;
	}

	if (fbr_has_alias_path(file1) && fbr_has_alias_path(file2)) {
		fbr_path_shared_ok(file1->alias.path);
		fbr_path_shared_ok(file2->alias.path);

		return fbr_path_name_cmp(&file1->alias.path->value, &file2->alias.path->value);
	}

	if (!fbr_has_alias_path(file1)) {
		assert_dev(file2->alias.path);
		return -1;
	}

	assert_zero_dev(fbr_has_alias_path(file2));

	return 1;
}
