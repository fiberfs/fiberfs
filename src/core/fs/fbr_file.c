/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include "fiberfs.h"
#include "fbr_fs.h"

struct fbr_file *
fbr_file_alloc(struct fbr_fs *fs, struct fbr_directory *parent,
    const struct fbr_path_name *filename)
{
	fbr_fs_ok(fs);
	assert(filename);

	struct fbr_path_shared *dirname = NULL;

	if (parent) {
		fbr_directory_ok(parent);
		dirname = parent->path;
	} else {
		assert_zero(fs->root_file);
		assert_zero(filename->len);

		dirname = fbr_path_shared_alloc(FBR_DIRNAME_ROOT);
	}

	struct fbr_file *file = fbr_path_storage_alloc(sizeof(*file),
		offsetof(struct fbr_file, path), dirname, filename);
	assert_dev(file);

	file->magic = FBR_FILE_MAGIC;

	if (parent) {
		file->inode = fbr_inode_gen(fs);
	} else {
		file->inode = FBR_INODE_ROOT;
		fbr_path_shared_release(dirname);
	}

	pt_assert(pthread_mutex_init(&file->refcount_lock, NULL));

	fbr_body_init(&file->body);

	fbr_fs_stat_add(&fs->stats.files);
	fbr_fs_stat_add(&fs->stats.files_total);

	if (parent) {
		fbr_directory_add_file(fs, parent, file);

		assert(file->parent_inode);
	} else {
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

	return fbr_path_cmp_file(&f1->path, &f2->path);
}

int
fbr_file_inode_cmp(const struct fbr_file *f1, const struct fbr_file *f2)
{
	fbr_file_ok(f1);
	fbr_file_ok(f2);

	if (f1->inode > f2->inode) {
		return 1;
	} else if (f1->inode < f2->inode) {
		return -1;
	}

	return 0;
}

void
fbr_file_ref_dindex(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	pt_assert(pthread_mutex_lock(&file->refcount_lock));
	fbr_file_ok(file);
	assert(file->refcounts.dindex);

	file->refcounts.dindex++;
	assert(file->refcounts.dindex);

	fbr_fs_stat_add(&fs->stats.file_refs);

	pt_assert(pthread_mutex_unlock(&file->refcount_lock));
}

void
fbr_file_release_dindex(struct fbr_fs *fs, struct fbr_file **file_ref)
{
	fbr_fs_ok(fs);
	assert(file_ref);

	struct fbr_file *file = *file_ref;
	fbr_file_ok(file);
	*file_ref = NULL;

	pt_assert(pthread_mutex_lock(&file->refcount_lock));
	fbr_file_ok(file);

	assert(file->refcounts.dindex);
	file->refcounts.dindex--;

	fbr_fs_stat_sub(&fs->stats.file_refs);

	int do_free = 0;
	if (!file->refcounts.dindex && !file->refcounts.inode) {
		do_free = 1;
	}

	pt_assert(pthread_mutex_unlock(&file->refcount_lock));

	if (do_free) {
		fbr_file_free(fs, file);
	}
}

void
fbr_file_ref_inode(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	pt_assert(pthread_mutex_lock(&file->refcount_lock));
	fbr_file_ok(file);

	file->refcounts.inode++;
	assert(file->refcounts.inode);

	fbr_fs_stat_add(&fs->stats.file_refs);

	pt_assert(pthread_mutex_unlock(&file->refcount_lock));
}

void
fbr_file_release_inode_lock(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_file_forget_inode_lock(fs, file, 1);
}

void
fbr_file_forget_inode_lock(struct fbr_fs *fs, struct fbr_file *file, fbr_refcount_t refs)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(refs);

	pt_assert(pthread_mutex_lock(&file->refcount_lock));
	fbr_file_ok(file);

	assert(file->refcounts.inode >= refs);
	file->refcounts.inode -= refs;

	fbr_fs_stat_sub_count(&fs->stats.file_refs, refs);

	// NOTE: caller must unlock when done
}

void
fbr_file_free(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	fbr_body_free(&file->body);
	fbr_path_free(&file->path);

	pt_assert(pthread_mutex_destroy(&file->refcount_lock));

	fbr_ZERO(file);
	free(file);

	fbr_fs_stat_sub(&fs->stats.files);
}

void
fbr_file_attr(const struct fbr_file *file, struct stat *st)
{
	fbr_file_ok(file);
	assert(st);

	fbr_ZERO(st);

	st->st_ino = file->inode;
	st->st_mode = file->mode;
	st->st_size = (off_t)file->size;
	st->st_uid = file->uid;
	st->st_gid = file->gid;

	st->st_nlink = 1;
}
