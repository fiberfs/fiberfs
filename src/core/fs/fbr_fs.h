/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_FS_H_INCLUDED_
#define _FBR_FS_H_INCLUDED_

#include <pthread.h>
#include <stddef.h>

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
	};
};

struct fbr_file {
	unsigned int				magic;
#define FBR_FILE_MAGIC				0x8F97F917

	struct fbr_filename			filename;

	unsigned long				inode;
	unsigned long				version;

	unsigned int				type;
	unsigned long				size;
	unsigned int				uid;
	unsigned int				gid;

	struct fbr_directory			*directory;

	TAILQ_ENTRY(fbr_file)			file_entry;
	RB_ENTRY(fbr_file)			filename_entry;
};

enum fbr_directory_state {
	FBR_DIRSTATE_NONE = 0,
	FBR_DIRSTATE_FETCH,
	FBR_DIRSTATE_OK,
	FBR_DIRSTATE_STALE,
	FBR_DIRSTATE_ERROR
};

RB_HEAD(fbr_filename_tree, fbr_file);

struct fbr_directory {
	unsigned int				magic;
#define FBR_DIRECTORY_MAGIC			0xADB900B1

	struct fbr_filename			dirname;

	enum fbr_directory_state		state;
	unsigned int				refcount;
	unsigned long				inode;

	pthread_mutex_t				lock;
	pthread_cond_t				cond;

	unsigned long				version;

	// TODO we need creation date and insertion date
	// creation date will tell us how often to look for updates

	RB_ENTRY(fbr_directory)			dindex_entry;

	TAILQ_HEAD(, fbr_file)			file_list;
	struct fbr_filename_tree		filename_tree;
};

struct fbr_fs {
	unsigned int				magic;
#define FBR_FS_MAGIC				0x150CC3D2

	struct fbr_directory			*root;
	struct fbr_dindex			*dindex;

	unsigned long				inode_next;

};

RB_HEAD(fbr_dindex_tree, fbr_directory);

// TODO Global inode search table: itable

void fbr_fs_init(struct fbr_fs *fs);
unsigned long fbr_fs_gen_inode(struct fbr_fs *fs);
void fbr_fs_free(struct fbr_fs *fs);

size_t fbr_filename_inline_len(size_t name_len);
void fbr_filename_init(struct fbr_filename *filename, char *filename_ptr, char *name,
	size_t name_len);
const char *fbr_filename_get(const struct fbr_filename *filename);
int fbr_filename_cmp(const struct fbr_filename *f1, const struct fbr_filename *f2);
void fbr_filename_free(struct fbr_filename *filename);

struct fbr_file *fbr_file_alloc(struct fbr_fs *fs, struct fbr_directory *directory,
	char *name, size_t name_len);
int fbr_file_cmp(const struct fbr_file *f1, const struct fbr_file *f2);
void fbr_file_free(struct fbr_file *file);

struct fbr_directory *fbr_directory_root_alloc(struct fbr_fs *fs);
struct fbr_directory *fbr_directory_alloc(struct fbr_fs *fs, char *name, size_t name_len);
int fbr_directory_cmp(const struct fbr_directory *d1, const struct fbr_directory *d2);
void fbr_directory_add(struct fbr_directory *directory, struct fbr_file *file);
void fbr_directory_set_state(struct fbr_directory *directory, enum fbr_directory_state state);
void fbr_directory_wait_state(struct fbr_directory *directory, enum fbr_directory_state state);
void fbr_directory_free(struct fbr_directory *directory);

struct fbr_dindex *fbr_dindex_alloc(void);
void fbr_dindex_add(struct fbr_dindex *dindex, struct fbr_directory *directory);
struct fbr_directory *fbr_dindex_get(struct fbr_dindex *dindex, unsigned long inode);
struct fbr_directory *fbr_dindex_get_noref(struct fbr_dindex *dindex, unsigned long inode);
void fbr_dindex_release(struct fbr_dindex *dindex, struct fbr_directory *directory);
void fbr_dindex_free(struct fbr_dindex *dindex);

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
