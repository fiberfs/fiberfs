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

// Note: can only be used during flush with a DIRSTATE_LOADING lock
void
fbr_alias_file_set(struct fbr_fs *fs, struct fbr_file *file, struct fbr_file *alias)
{
	assert_dev(fs);
	fbr_file_ok(file);
	fbr_file_ok(alias);
	assert_zero(alias->alias.file);

	fbr_rlog(FBR_LOG_FS, "ALIAS inode: %lu gen: %lu to inode: %lu gen: %lu",
		file->inode, file->generation, alias->inode, alias->generation);

	assert_zero(file->has_alias_file);
	assert_zero(file->alias.file);

	file->alias.file = fbr_inode_add(fs, alias);
	file->has_alias_file = 1;
}

void
fbr_alias_file_free(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(file->alias.file);
	assert_dev(file->has_alias_file);

	file->has_alias_file = 0;

	fbr_inode_release(fs, &file->alias.file);
	assert_zero_dev(file->alias.file);
}

struct fbr_file *
fbr_alias_file_find(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	if (file->has_alias_file) {
		assert_dev(file->alias.file);

		struct fbr_file *alias = fbr_alias_file_get(fs, file->alias.file);
		assert_dev(alias);

		return alias;
	}

	return file;
}

struct fbr_file *
fbr_alias_file_get(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);

	while (file) {
		fbr_file_ok(file);
		assert_zero(S_ISDIR(file->mode));

		struct fbr_path_name filename;
		fbr_path_get_file(&file->path, &filename);

		fbr_rlog(FBR_LOG_FS, "ALIAS name: '%s' inode: %lu gen: %lu", filename.name,
			file->inode, file->generation);

		if (!file->has_alias_file) {
			assert_zero_dev(file->alias.file);
			break;
		}

		file = file->alias.file;
		assert_dev(file);
	}

	return file;
}

void
fbr_alias_free(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	if (fbr_has_alias_path(file)) {
		fbr_alias_path_free(fs, file);
	}

	if (file->has_alias_file) {
		fbr_alias_file_free(fs, file);
	}
}
