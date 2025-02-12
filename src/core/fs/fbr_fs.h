/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_FS_H_INCLUDED_
#define _FBR_FS_H_INCLUDED_

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "data/queue.h"
#include "data/tree.h"

#define FBR_FILE_EMBED_LEN			16

enum FBR_FILENAME_LAYOUT {
	FBR_FILENAME_NULL = 0,
	FBR_FILENAME_EMBED,
	FBR_FILENAME_INLINE,
	FBR_FILENAME_CONST,
	FBR_FILENAME_ALLOC,
	__FBR_FILENAME_LAYOUT_END
};

struct fbr_filename {
	unsigned char				layout;
	unsigned short				len;
	union {
		char				name_data[FBR_FILE_EMBED_LEN];
		char				*name_ptr;
		const char			*cname_ptr;
	};
};

struct fbr_file {
	unsigned int				magic;
#define FBR_FILE_MAGIC				0x8F97F917

	struct fbr_filename			filename;

	unsigned int				refcount;
	pthread_mutex_t				lock;

	unsigned long				inode;
	unsigned long				version;

	unsigned int				mode;
	unsigned long				size;
	unsigned int				uid;
	unsigned int				gid;

	TAILQ_ENTRY(fbr_file)			file_entry;
	RB_ENTRY(fbr_file)			filename_entry;
	RB_ENTRY(fbr_file)			inode_entry;
};

enum fbr_directory_state {
	FBR_DIRSTATE_NONE = 0,
	FBR_DIRSTATE_LOADING,
	FBR_DIRSTATE_OK,
	FBR_DIRSTATE_STALE,
	FBR_DIRSTATE_ERROR
};

RB_HEAD(fbr_filename_tree, fbr_file);
RB_HEAD(fbr_inode_tree, fbr_file);

struct fbr_directory {
	unsigned int				magic;
#define FBR_DIRECTORY_MAGIC			0xADB900B1

	struct fbr_filename			dirname;

	enum fbr_directory_state		state;
	unsigned int				refcount;
	unsigned long				inode;

	pthread_mutex_t				cond_lock;
	pthread_cond_t				cond;

	unsigned long				version;

	// TODO we need creation date and insertion date
	// creation date will tell us how often to look for updates

	RB_ENTRY(fbr_directory)			dindex_entry;

	TAILQ_HEAD(, fbr_file)			file_list;
	struct fbr_filename_tree		filename_tree;
};

struct fbr_fs_stats {
	unsigned long				directories;
	unsigned long				directories_total;
	unsigned long				directory_refs;
	unsigned long				files;
	unsigned long				files_total;
	unsigned long				file_refs;
};

struct fbr_fs {
	unsigned int				magic;
#define FBR_FS_MAGIC				0x150CC3D2

	struct fbr_inode			*inode;
	struct fbr_dindex			*dindex;

	struct fbr_directory			*root;

	struct fbr_fs_stats			stats;
};

RB_HEAD(fbr_dindex_tree, fbr_directory);

void fbr_fs_init(struct fbr_fs *fs);
void fbr_fs_set_root(struct fbr_fs *fs, struct fbr_directory *root);
void fbr_fs_release_root(struct fbr_fs *fs);
void fbr_fs_free(struct fbr_fs *fs);

void fbr_fs_stat_add_count(unsigned long *stat, unsigned long value);
void fbr_fs_stat_add(unsigned long *stat);
void fbr_fs_stat_sub_count(unsigned long *stat, unsigned long value);
void fbr_fs_stat_sub(unsigned long *stat);

struct fbr_inode *fbr_inodes_alloc(void);
unsigned long fbr_inode_gen(struct fbr_fs *fs);
void fbr_inode_add(struct fbr_fs *fs, struct fbr_file *file);
struct fbr_file *fbr_inode_get(struct fbr_fs *fs, unsigned long file_inode);
struct fbr_file *fbr_inode_ref(struct fbr_fs *fs, unsigned long file_inode);
void fbr_inode_release(struct fbr_fs *fs, unsigned long inode);
void fbr_inode_forget(struct fbr_fs *fs, unsigned long inode, unsigned int refs);
void fbr_inode_delete(struct fbr_fs *fs, struct fbr_file *file);
void fbr_inodes_free(struct fbr_fs *fs);

size_t fbr_filename_inline_len(size_t name_len);
void fbr_filename_init(struct fbr_filename *filename, char *filename_ptr, char *name,
	size_t name_len);
const char *fbr_filename_get(const struct fbr_filename *filename);
int fbr_filename_cmp(const struct fbr_filename *f1, const struct fbr_filename *f2);
void fbr_filename_free(struct fbr_filename *filename);

struct fbr_file *fbr_file_root_alloc(struct fbr_fs *fs);
struct fbr_file *fbr_file_alloc(struct fbr_fs *fs, struct fbr_directory *directory,
	char *name, size_t name_len, mode_t mode);
int fbr_file_cmp(const struct fbr_file *f1, const struct fbr_file *f2);
int fbr_file_inode_cmp(const struct fbr_file *f1, const struct fbr_file *f2);
void fbr_file_release(struct fbr_fs *fs, struct fbr_file *file);
void fbr_file_free(struct fbr_fs *fs, struct fbr_file *file);
void fbr_file_attr(struct fbr_file *file, struct stat *st);
uint64_t fbr_file_to_fh(struct fbr_file *file);
struct fbr_file *fbr_file_fh(uint64_t fd);

RB_PROTOTYPE(fbr_filename_tree, fbr_file, filename_entry, fbr_file_cmp)

struct fbr_directory *fbr_directory_root_alloc(struct fbr_fs *fs);
struct fbr_directory *fbr_directory_alloc(struct fbr_fs *fs, char *name, size_t name_len);
int fbr_directory_cmp(const struct fbr_directory *d1, const struct fbr_directory *d2);
void fbr_directory_add(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_file *file);
void fbr_directory_set_state(struct fbr_directory *directory, enum fbr_directory_state state);
void fbr_directory_wait_ok(struct fbr_directory *directory);
struct fbr_file *fbr_directory_find(struct fbr_directory *directory, const char *filename);

struct fbr_dindex *fbr_dindex_alloc(void);
void fbr_dindex_add(struct fbr_fs *fs, struct fbr_directory *directory);
struct fbr_directory *fbr_dindex_get(struct fbr_fs *fs, unsigned long inode);
void fbr_dindex_forget(struct fbr_fs *fs, unsigned long inode, unsigned int refs);
void fbr_dindex_release(struct fbr_fs *fs, struct fbr_directory *directory);
void fbr_dindex_release_count(struct fbr_fs *fs, struct fbr_directory *directory,
	unsigned int refs);
void fbr_dindex_free(struct fbr_fs *fs);

#define fbr_directory_release			fbr_dindex_release
#define fbr_directory_release_count		fbr_dindex_release_count

#define fbr_fs_ok(fs)						\
{								\
	assert(fs);						\
	assert((fs)->magic == FBR_FS_MAGIC);			\
}
#define fbr_file_ok(file)					\
{								\
	assert(file);						\
	assert((file)->magic == FBR_FILE_MAGIC);		\
}
#define fbr_directory_ok(dir)					\
{								\
	assert(dir);						\
	assert((dir)->magic == FBR_DIRECTORY_MAGIC);		\
}

#endif /* _FBR_FS_H_INCLUDED_ */
