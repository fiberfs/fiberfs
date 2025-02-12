/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "fuse/fbr_fuse_ops.h"

struct fbr_file *
fbr_file_alloc(struct fbr_fs *fs, struct fbr_directory *directory, char *name,
    size_t name_len)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(name);

	size_t inline_len = fbr_filename_inline_len(name_len);
	char *inline_ptr = NULL;

	struct fbr_file *file = calloc(1, sizeof(*file) + inline_len);
	fbr_fuse_ASSERT(file, NULL);

	if (inline_len) {
		inline_ptr = (char*)file + sizeof(*file);
	}

	file->magic = FBR_FILE_MAGIC;
	file->inode = fbr_inode_gen(fs);

	fbr_filename_init(&file->filename, inline_ptr, name, name_len);

	assert_zero(pthread_mutex_init(&file->lock, NULL));

	fbr_fs_stat_add(&fs->stats.files);
	fbr_fs_stat_add(&fs->stats.files_total);

	fbr_file_ok(file);

	fbr_directory_add(fs, directory, file);

	return file;
}

int
fbr_file_cmp(const struct fbr_file *f1, const struct fbr_file *f2)
{
	fbr_file_ok(f1);
	fbr_file_ok(f2);

	return fbr_filename_cmp(&f1->filename, &f2->filename);
}

void
_fbr_file_free(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	assert_zero(pthread_mutex_destroy(&file->lock));

	fbr_filename_free(&file->filename);

	fbr_ZERO(file);

	free(file);

	fbr_fs_stat_sub(&fs->stats.files);
}

static void
_file_release(struct fbr_fs *fs, struct fbr_file *file, unsigned int refs)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(refs);

	assert_zero(pthread_mutex_lock(&file->lock));
	fbr_file_ok(file);

	assert(file->refcount >= refs);
	file->refcount -= refs;

	fbr_fs_stat_sub(&fs->stats.file_refs);

	if (file->refcount) {
		assert_zero(pthread_mutex_unlock(&file->lock));
		return;
	}

	assert_zero(pthread_mutex_unlock(&file->lock));

	// TODO inode?

	_fbr_file_free(fs, file);
}

void
fbr_file_release(struct fbr_fs *fs, struct fbr_file *file)
{
	_file_release(fs, file, 1);
}

void
fbr_file_release_count(struct fbr_fs *fs, struct fbr_file *file, unsigned int refs)
{
	_file_release(fs, file, refs);
}
