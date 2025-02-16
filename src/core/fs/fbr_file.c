/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/fuse/fbr_fuse_ops.h"

struct fbr_file *
fbr_file_alloc(struct fbr_fs *fs, struct fbr_directory *parent, char *name,
    size_t name_len, mode_t mode)
{
	fbr_fs_ok(fs);
	assert(name);

	struct fbr_file *file = fbr_inline_alloc(sizeof(*file),
		offsetof(struct fbr_file, filename), name, name_len);
	assert_zero(strncmp(fbr_filename_get(&file->filename), name, name_len));

	file->magic = FBR_FILE_MAGIC;
	file->mode = mode;

	if (!name_len) {
		assert_zero(fs->root);
		file->inode = FBR_INODE_ROOT;
	} else {
		file->inode = fbr_inode_gen(fs);
	}

	assert_zero(pthread_mutex_init(&file->refcount_lock, NULL));

	fbr_fs_stat_add(&fs->stats.files);
	fbr_fs_stat_add(&fs->stats.files_total);

	if (parent) {
		fbr_directory_ok(parent);
		fbr_directory_add(fs, parent, file);

		assert(file->parent_inode);
	} else {
		assert(file->inode == FBR_INODE_ROOT);
		assert_zero(file->parent_inode);
	}

	fbr_file_ok(file);

	return file;
}

int
fbr_file_cmp(const struct fbr_file *f1, const struct fbr_file *f2)
{
	fbr_file_ok(f1);
	fbr_file_ok(f2);

	return fbr_filename_cmp(&f1->filename, &f2->filename);
}

int
fbr_file_inode_cmp(const struct fbr_file *f1, const struct fbr_file *f2)
{
	fbr_file_ok(f1);
	fbr_file_ok(f2);

	return f1->inode - f2->inode;
}

static void
_refcounts_sum(struct fbr_file_refcounts *refcounts)
{
	assert(refcounts);

	refcounts->all = refcounts->dindex + refcounts->inode;
	assert(refcounts->all >= refcounts->dindex);
	assert(refcounts->all >= refcounts->inode);
}

void
fbr_file_ref_dindex(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_file_ok(file);

	assert_zero(pthread_mutex_lock(&file->refcount_lock));
	fbr_file_ok(file);
	assert(file->refcounts.dindex);

	file->refcounts.dindex++;
	assert(file->refcounts.dindex);

	_refcounts_sum(&file->refcounts);

	fbr_fs_stat_add(&fs->stats.file_refs);

	assert_zero(pthread_mutex_unlock(&file->refcount_lock));
}

void
fbr_file_release_dindex(struct fbr_fs *fs, struct fbr_file *file,
    struct fbr_file_refcounts *refcounts)
{
	fbr_file_ok(file);
	assert(refcounts);

	assert_zero(pthread_mutex_lock(&file->refcount_lock));
	fbr_file_ok(file);

	assert(file->refcounts.dindex);
	file->refcounts.dindex--;

	_refcounts_sum(&file->refcounts);

	fbr_fs_stat_sub(&fs->stats.file_refs);

	memcpy(refcounts, &file->refcounts, sizeof(*refcounts));

	assert_zero(pthread_mutex_unlock(&file->refcount_lock));
}

void
fbr_file_ref_inode(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_file_ok(file);

	assert_zero(pthread_mutex_lock(&file->refcount_lock));
	fbr_file_ok(file);

	file->refcounts.inode++;
	assert(file->refcounts.inode);

	_refcounts_sum(&file->refcounts);

	fbr_fs_stat_add(&fs->stats.file_refs);

	assert_zero(pthread_mutex_unlock(&file->refcount_lock));
}

void
fbr_file_release_inode(struct fbr_fs *fs, struct fbr_file *file,
    struct fbr_file_refcounts *refcounts)
{
	fbr_file_forget_inode(fs, file, 1, refcounts);
}

void
fbr_file_forget_inode(struct fbr_fs *fs, struct fbr_file *file, fbr_refcount_t refs,
    struct fbr_file_refcounts *refcounts)
{
	fbr_file_ok(file);
	assert(refcounts);

	assert_zero(pthread_mutex_lock(&file->refcount_lock));
	fbr_file_ok(file);

	assert(file->refcounts.inode >= refs);
	file->refcounts.inode -= refs;

	_refcounts_sum(&file->refcounts);

	fbr_fs_stat_sub_count(&fs->stats.file_refs, refs);

	memcpy(refcounts, &file->refcounts, sizeof(*refcounts));

	assert_zero(pthread_mutex_unlock(&file->refcount_lock));
}

void
fbr_file_free(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	assert_zero(pthread_mutex_destroy(&file->refcount_lock));

	fbr_filename_free(&file->filename);

	fbr_ZERO(file);

	free(file);

	fbr_fs_stat_sub(&fs->stats.files);
}

void
fbr_file_attr(struct fbr_file *file, struct stat *st)
{
	fbr_file_ok(file);
	assert(st);

	fbr_ZERO(st);

	st->st_ino = file->inode;
	st->st_mode = file->mode;
	st->st_size = file->size;
	st->st_uid = file->uid;
	st->st_gid = file->gid;

	st->st_nlink = 1;
}
