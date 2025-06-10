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

static struct fbr_file *
_file_alloc(struct fbr_fs *fs, struct fbr_directory *parent,
    const struct fbr_path_name *filename, int create)
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
		file->state = FBR_FILE_OK;
		file->inode = FBR_INODE_ROOT;
		fbr_path_shared_release(dirname);
	}

	pt_assert(pthread_mutex_init(&file->refcount_lock, NULL));
	pt_assert(pthread_mutex_init(&file->lock, NULL));
	pt_assert(pthread_cond_init(&file->update, NULL));

	fbr_body_init(&file->body);

	fbr_fs_stat_add(&fs->stats.files);
	fbr_fs_stat_add(&fs->stats.files_total);

	if (parent) {
		if (!create) {
			fbr_directory_add_file(fs, parent, file);
		}

		file->parent_inode = parent->inode;
	} else {
		assert_zero(create);
		assert_zero(file->parent_inode);
	}

	fbr_file_ok(file);

	return file;
}

struct fbr_file *
fbr_file_alloc(struct fbr_fs *fs, struct fbr_directory *parent,
    const struct fbr_path_name *filename)
{
	return _file_alloc(fs, parent, filename, 0);
}

struct fbr_file *
fbr_file_alloc_new(struct fbr_fs *fs, struct fbr_directory *parent,
    const struct fbr_path_name *filename)
{
	return _file_alloc(fs, parent, filename, 1);
}

/*
 * Locking is required when reading/writing the body and attributes
 */
void
fbr_file_LOCK(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_fuse_lock(fs->fuse_ctx, &file->lock);
}

void
fbr_file_UNLOCK(struct fbr_file *file)
{
	fbr_file_ok(file);
	pt_assert(pthread_mutex_unlock(&file->lock));
}

int
fbr_file_ptr_cmp(const struct fbr_file_ptr *p1, const struct fbr_file_ptr *p2)
{
	assert(p1);
	assert(p2);

	return fbr_file_cmp(p1->file, p2->file);
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
		assert_zero(file->refcounts.wbuffer);
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
fbr_file_ref_wbuffer(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(file->refcounts.inode);

	// This is safe, fio always takes an inode reference first
	fbr_atomic_add(&file->refcounts.wbuffer, 1);
	assert(file->refcounts.wbuffer);
}

void
fbr_file_release_wbuffer(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(file->refcounts.inode);

	assert(file->refcounts.wbuffer);
	fbr_atomic_sub(&file->refcounts.wbuffer, 1);
}

int
fbr_file_has_wbuffer(struct fbr_file *file)
{
	fbr_file_ok(file);

	if (file->refcounts.wbuffer) {
		return 1;
	}

	return 0;
}

void
fbr_file_free(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	fbr_body_free(&file->body);
	fbr_path_free(&file->path);
	fbr_file_ptrs_free(file);

	pt_assert(pthread_mutex_destroy(&file->refcount_lock));
	pt_assert(pthread_mutex_destroy(&file->lock));
	pt_assert(pthread_cond_destroy(&file->update));

	fbr_ZERO(file);
	free(file);

	fbr_fs_stat_sub(&fs->stats.files);
}

static inline int
_file_ptr_empty(struct fbr_file_ptr *file_ptr)
{
	assert_dev(file_ptr);

	if (file_ptr->file) {
		return 0;
	}

	return 1;
}

static struct fbr_file_ptr_slab *
_file_ptr_slab_alloc(void)
{
	size_t ptrs_size = FBR_FILE_SLAB_DEFAULT_PTRS * sizeof(struct fbr_file_ptr);
	struct fbr_file_ptr_slab *ptr_slab = calloc(1, sizeof(*ptr_slab) + ptrs_size);
	assert(ptr_slab);

	ptr_slab->magic = FBR_FILE_PTR_SLAB_MAGIC;
	ptr_slab->length = FBR_FILE_SLAB_DEFAULT_PTRS;

	return ptr_slab;
}

static void
_file_pointer_init(struct fbr_file *file, struct fbr_file_ptr *file_ptr)
{
	assert_dev(file);
	assert_dev(file_ptr);
	assert_zero_dev(file_ptr->file);

	file_ptr->file = file;
}

// Note: only use while under a directory loading state
struct fbr_file_ptr *
fbr_file_ptr_get(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	for (size_t i = 0; i < fbr_array_len(file->ptr_head.ptrs); i++) {
		struct fbr_file_ptr *file_ptr = &file->ptr_head.ptrs[i];
		if (_file_ptr_empty(file_ptr)) {
			_file_pointer_init(file, file_ptr);
			return file_ptr;
		}
	}

	struct fbr_file_ptr_slab *ptr_slab = file->ptr_head.next;

	if (ptr_slab) {
		fbr_file_ptr_slab_ok(ptr_slab);

		for (size_t i = 0; i < ptr_slab->length; i++) {
			struct fbr_file_ptr *file_ptr = &ptr_slab->ptrs[i];
			if (_file_ptr_empty(file_ptr)) {
				_file_pointer_init(file, file_ptr);
				return file_ptr;
			}
		}
	}

	ptr_slab = _file_ptr_slab_alloc();
	fbr_file_ptr_slab_ok(ptr_slab);

	ptr_slab->next = file->ptr_head.next;
	file->ptr_head.next = ptr_slab;

	fbr_fs_stat_add(&fs->stats.file_ptr_slabs);

	struct fbr_file_ptr *file_ptr = &ptr_slab->ptrs[0];
	_file_pointer_init(file, file_ptr);

	return file_ptr;
}

void
fbr_file_ptr_free(struct fbr_file_ptr *file_ptr)
{
	fbr_file_ptr_ok(file_ptr);

	file_ptr->file = NULL;
}

static void
_file_ptr_slab_free(struct fbr_file_ptr_slab *ptr_slab)
{
	assert_dev(ptr_slab);

	if (fbr_assert_is_dev()) {
		for (size_t i = 0; i < ptr_slab->length; i++) {
			assert(_file_ptr_empty(&ptr_slab->ptrs[i]));
		}
	}

	fbr_ZERO(ptr_slab);
	free(ptr_slab);
}

void
fbr_file_ptrs_free(struct fbr_file *file)
{
	fbr_file_ok(file);

	if (fbr_assert_is_dev()) {
		for (size_t i = 0; i < fbr_array_len(file->ptr_head.ptrs); i++) {
			assert(_file_ptr_empty(&file->ptr_head.ptrs[i]));
		}
	}

	while (file->ptr_head.next) {
		struct fbr_file_ptr_slab *ptr_slab = file->ptr_head.next;
		fbr_file_ptr_slab_ok(ptr_slab);

		file->ptr_head.next = ptr_slab->next;

		_file_ptr_slab_free(ptr_slab);

	}
}

void
fbr_file_attr(struct fbr_fs *fs, struct fbr_file *file, struct stat *st)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(st);

	fbr_ZERO(st);

	fbr_file_LOCK(fs, file);

	st->st_ino = file->inode;
	st->st_mode = file->mode;
	st->st_size = (off_t)file->size;
	st->st_uid = file->uid;
	st->st_gid = file->gid;
	st->st_nlink = 1;

	fbr_file_UNLOCK(file);
}
