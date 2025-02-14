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
fbr_file_root_alloc(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	// TODO mode ok?
	struct fbr_file *root_file = fbr_file_alloc(fs, NULL, "", 0, S_IFDIR | 0755);
	fbr_file_ok(root_file);

	return root_file;
}

struct fbr_file *
fbr_file_alloc(struct fbr_fs *fs, struct fbr_directory *directory, char *name,
    size_t name_len, mode_t mode)
{
	fbr_fs_ok(fs);
	assert(name);

	size_t inline_len = fbr_filename_inline_len(name_len);
	char *inline_ptr = NULL;

	struct fbr_file *file = calloc(1, sizeof(*file) + inline_len);
	fbr_fuse_ASSERT(file, NULL);

	if (inline_len) {
		inline_ptr = (char*)file + sizeof(*file);
	}

	file->magic = FBR_FILE_MAGIC;
	file->mode = mode;

	if (!name_len) {
		file->inode = 1;
	} else {
		file->inode = fbr_inode_gen(fs);
	}

	fbr_filename_init(&file->filename, inline_ptr, name, name_len);

	assert_zero(pthread_mutex_init(&file->refcount_lock, NULL));

	fbr_fs_stat_add(&fs->stats.files);
	fbr_fs_stat_add(&fs->stats.files_total);

	fbr_file_ok(file);

	if (directory) {
		fbr_directory_ok(directory);
		fbr_directory_add(fs, directory, file);
	}

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

void
fbr_file_ref_dindex(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_file_ok(file);

	assert_zero(pthread_mutex_lock(&file->refcount_lock));
	fbr_file_ok(file);
	assert(file->refcounts.dindex);

	file->refcounts.dindex++;
	assert(file->refcounts.dindex);

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
fbr_file_forget_inode(struct fbr_fs *fs, struct fbr_file *file, unsigned int refs,
    struct fbr_file_refcounts *refcounts)
{
	fbr_file_ok(file);
	assert(refcounts);

	assert_zero(pthread_mutex_lock(&file->refcount_lock));
	fbr_file_ok(file);

	assert(file->refcounts.inode >= refs);
	file->refcounts.inode -= refs;

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

uint64_t
fbr_file_to_fh(struct fbr_file *file)
{
	fbr_file_ok(file);

	return (uint64_t)file;
}

struct fbr_file *
fbr_file_fh(uint64_t fh)
{
	struct fbr_file *file = (struct fbr_file*)fh;
	fbr_file_ok(file);

	return file;
}
