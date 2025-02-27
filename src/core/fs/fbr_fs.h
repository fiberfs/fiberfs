/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_FS_H_INCLUDED_
#define _FBR_FS_H_INCLUDED_

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fbr_id.h"
#include "fbr_path.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/context/fbr_callback.h"
#include "data/queue.h"
#include "data/tree.h"

#define FBR_INODE_ROOT				FUSE_ROOT_ID
#define FBR_READDIR_SIZE			4096
#define FBR_BODY_DEFAULT_CHUNKS			4
#define FBR_BODY_SLAB_DEFAULT_CHUNKS		32
#define FBR_FREADER_DEFAULT_CHUNKS		2

typedef unsigned long fbr_inode_t;
typedef unsigned int fbr_refcount_t;

enum fbr_chunk_state {
	FBR_CHUNK_NONE = 0,
	FBR_CHUNK_UNREAD,
	FBR_CHUNK_LOADING,
	FBR_CHUNK_READ
};

struct fbr_chunk {
	unsigned int				magic;
#define FBR_CHUNK_MAGIC				0xA8E5D947

	enum fbr_chunk_state			state;

	fbr_id_t				id;

	size_t					offset;
	size_t					length;
	fbr_refcount_t				refcount;

	uint8_t					*data;
	void					*chttp;

	struct fbr_chunk			*next;
};

struct fbr_chunk_slab {
	unsigned int				magic;
#define FBR_CHUNK_SLAB_MAGIC			0x68469049

	unsigned int				chunks_len;

	struct fbr_chunk_slab			*next;

	struct fbr_chunk			chunks[];
};

struct fbr_body {
	pthread_mutex_t				lock;
	pthread_cond_t				update;

	struct {
		struct fbr_chunk		chunks[FBR_BODY_DEFAULT_CHUNKS];
		struct fbr_chunk_slab		*next;
	}  slabhead;

	struct fbr_chunk			*chunks;
	struct fbr_chunk			*chunk_ptr;
};

struct fbr_file_refcounts {
	fbr_refcount_t				dindex;
	fbr_refcount_t				inode;
};

struct fbr_file {
	unsigned int				magic;
#define FBR_FILE_MAGIC				0x8F97F917

	struct fbr_path				path;

	struct fbr_file_refcounts		refcounts;
	pthread_mutex_t				refcount_lock;

	fbr_inode_t				inode;
	fbr_inode_t				parent_inode;
	unsigned long				version;

	unsigned int				mode;
	unsigned long				size;
	unsigned int				uid;
	unsigned int				gid;

	TAILQ_ENTRY(fbr_file)			file_entry;
	RB_ENTRY(fbr_file)			filename_entry;
	RB_ENTRY(fbr_file)			inode_entry;

	struct fbr_body				body;
};

enum fbr_directory_state {
	FBR_DIRSTATE_NONE = 0,
	FBR_DIRSTATE_LOADING,
	FBR_DIRSTATE_STALE,
	FBR_DIRSTATE_OK,
	FBR_DIRSTATE_ERROR
};

RB_HEAD(fbr_filename_tree, fbr_file);
RB_HEAD(fbr_inodes_tree, fbr_file);

struct fbr_directory {
	unsigned int				magic;
#define FBR_DIRECTORY_MAGIC			0xADB900B1

	struct fbr_path				dirname;

	enum fbr_directory_state		state;
	fbr_refcount_t				refcount;
	fbr_inode_t				inode;

	pthread_mutex_t				update_lock;
	pthread_cond_t				update;

	unsigned long				version;

	// TODO we need creation date and insertion date
	// creation date will tell us how often to look for updates

	struct fbr_file				*file;

	RB_ENTRY(fbr_directory)			dindex_entry;
	TAILQ_ENTRY(fbr_directory)		lru_entry;
	TAILQ_HEAD(, fbr_file)			file_list;
	struct fbr_filename_tree		filename_tree;

	unsigned int				dindexed:1;
};

struct fbr_dirbuffer {
	char					buffer[FBR_READDIR_SIZE];

	size_t					max;
	size_t					pos;
	size_t					free;

	unsigned int				full:1;
};

struct fbr_dreader {
	unsigned int				magic;
#define FBR_DREADER_MAGIC			0xF3CFAEDF

	struct fbr_directory			*directory;

	struct fbr_file				*position;

	unsigned int				read_dot:1;
	unsigned int				read_dotdot:1;
	unsigned int				end:1;
};

struct fbr_freader {
	unsigned int				magic;
#define FBR_FREADER_MAGIC			0xC476C0F5

	struct fbr_file				*file;

	struct fbr_chunk			*_chunks[FBR_FREADER_DEFAULT_CHUNKS];

	struct fbr_chunk			**chunks;
	size_t					chunks_pos;
	size_t					chunks_len;

	size_t					releases;
	size_t					softs;
};

struct fbr_fs_stats {
	unsigned long				directories;
	unsigned long				directories_dindex;
	unsigned long				directories_total;
	unsigned long				directory_refs;
	unsigned long				files;
	unsigned long				files_total;
	unsigned long				file_refs;
	unsigned long				requests;
	unsigned long				requests_total;
};

typedef void (fbr_fs_chunk_f)(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk);

struct fbr_fs {
	unsigned int				magic;
#define FBR_FS_MAGIC				0x150CC3D2

	struct fbr_inodes			*inodes;
	struct fbr_dindex			*dindex;

	struct fbr_directory			*root;

	fbr_fs_chunk_f				*fs_chunk_cb;

	struct fbr_fs_stats			stats;
};

RB_HEAD(fbr_dindex_tree, fbr_directory);

extern const struct fbr_path_name *FBR_DIRNAME_ROOT;

typedef void (fbr_inodes_debug_f)(struct fbr_fs *fs, struct fbr_file *file);
typedef void (fbr_dindex_debug_f)(struct fbr_fs *fs, struct fbr_directory *directory);

struct fbr_fs *fbr_fs_alloc(void);
void fbr_fs_set_root(struct fbr_fs *fs, struct fbr_directory *root);
void fbr_fs_release_root(struct fbr_fs *fs, int release_root_inode);
void fbr_fs_free(struct fbr_fs *fs);

void fbr_fs_stat_add_count(unsigned long *stat, unsigned long value);
void fbr_fs_stat_add(unsigned long *stat);
void fbr_fs_stat_sub_count(unsigned long *stat, unsigned long value);
void fbr_fs_stat_sub(unsigned long *stat);

fbr_id_t fbr_id_gen(void);
size_t fbr_id_string(fbr_id_t value, char *buffer, size_t buffer_len);

void fbr_inodes_alloc(struct fbr_fs *fs);
unsigned long fbr_inode_gen(struct fbr_fs *fs);
void fbr_inode_add(struct fbr_fs *fs, struct fbr_file *file);
struct fbr_file *fbr_inode_take(struct fbr_fs *fs, fbr_inode_t inode);
void fbr_inode_release(struct fbr_fs *fs, struct fbr_file **file_ref);
void fbr_inode_forget(struct fbr_fs *fs, fbr_inode_t inode, fbr_refcount_t refs);
void fbr_inodes_debug(struct fbr_fs *fs, fbr_inodes_debug_f *callback);
void fbr_inodes_free_all(struct fbr_fs *fs);

struct fbr_file *fbr_file_alloc(struct fbr_fs *fs, struct fbr_directory *parent,
	const struct fbr_path_name *filename, mode_t mode);
int fbr_file_cmp(const struct fbr_file *f1, const struct fbr_file *f2);
int fbr_file_inode_cmp(const struct fbr_file *f1, const struct fbr_file *f2);
void fbr_file_ref_dindex(struct fbr_fs *fs, struct fbr_file *file);
void fbr_file_release_dindex(struct fbr_fs *fs, struct fbr_file **file_ref);
void fbr_file_ref_inode(struct fbr_fs *fs, struct fbr_file *file);
void fbr_file_release_inode_lock(struct fbr_fs *fs, struct fbr_file *file);
void fbr_file_forget_inode_lock(struct fbr_fs *fs, struct fbr_file *file, fbr_refcount_t refs);
void fbr_file_free(struct fbr_fs *fs, struct fbr_file *file);
void fbr_file_attr(struct fbr_file *file, struct stat *st);

void fbr_body_init(struct fbr_body *body);
void fbr_body_chunk_add(struct fbr_file *file, fbr_id_t id, size_t offset, size_t length);
void fbr_chunk_unread(struct fbr_chunk *chunk);
void fbr_chunk_take(struct fbr_chunk *chunk);
void fbr_chunk_release(struct fbr_chunk **chunk_ref);
void fbr_chunk_soft_release(struct fbr_chunk **chunk_ref);
void fbr_body_free(struct fbr_body *body);

RB_PROTOTYPE(fbr_filename_tree, fbr_file, filename_entry, fbr_file_cmp)

struct fbr_directory *fbr_directory_root_alloc(struct fbr_fs *fs);
struct fbr_directory *fbr_directory_alloc(struct fbr_fs *fs, const struct fbr_path_name *dirname,
	fbr_inode_t inode);
int fbr_directory_cmp(const struct fbr_directory *d1, const struct fbr_directory *d2);
void fbr_directory_add_file(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_file *file);
void fbr_directory_set_state(struct fbr_directory *directory, enum fbr_directory_state state);
void fbr_directory_wait_ok(struct fbr_directory *directory);
struct fbr_file *fbr_directory_find_file(struct fbr_directory *directory, const char *filename);

void fbr_dindex_alloc(struct fbr_fs *fs);
void fbr_dindex_add(struct fbr_fs *fs, struct fbr_directory *directory);
struct fbr_directory *fbr_dindex_take(struct fbr_fs *fs, const struct fbr_path_name *dirname);
void fbr_dindex_release(struct fbr_fs *fs, struct fbr_directory **directory_ref);
void fbr_dindex_lru_purge(struct fbr_fs *fs, size_t lru_max);
void fbr_dindex_debug(struct fbr_fs *fs, fbr_dindex_debug_f *callback);
void fbr_dindex_free_all(struct fbr_fs *fs);

struct fbr_dreader *fbr_dreader_alloc(struct fbr_fs *fs, struct fbr_directory *directory);
void fbr_dirbuffer_init(struct fbr_dirbuffer *dbuf, size_t fuse_size);
void fbr_dirbuffer_add(struct fbr_request *request, struct fbr_dirbuffer *dbuf,
	const char *name, struct stat *st);
void fbr_dreader_free(struct fbr_fs *fs, struct fbr_dreader *reader);

struct fbr_freader *fbr_freader_alloc(struct fbr_fs *fs, struct fbr_file *file);
int fbr_freader_ready(struct fbr_freader *reader);
void fbr_freader_pull_chunks(struct fbr_fs *fs, struct fbr_freader *reader, size_t offset,
	size_t size);
size_t fbr_freader_copy_chunks(struct fbr_fs *fs, struct fbr_freader *reader, char *buffer,
	size_t offset, size_t buffer_len);
void fbr_freader_release_chunks(struct fbr_fs *fs, struct fbr_freader *reader, size_t offset,
	size_t size);
void fbr_freader_free(struct fbr_fs *fs, struct fbr_freader *reader);

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
#define fbr_dreader_ok(dreader)					\
{								\
	assert(dreader);					\
	assert((dreader)->magic == FBR_DREADER_MAGIC);		\
}
#define fbr_freader_ok(freader)					\
{								\
	assert(freader);					\
	assert((freader)->magic == FBR_FREADER_MAGIC);		\
}
#define fbr_chunk_ok(chunk)					\
{								\
	assert(chunk);						\
	assert((chunk)->magic == FBR_CHUNK_MAGIC);		\
}
#define fbr_chunk_slab_ok(slab)					\
{								\
	assert(slab);						\
	assert((slab)->magic == FBR_CHUNK_SLAB_MAGIC);		\
}
#define fbr_fs_int64(obj)					\
	((uint64_t)(obj))

#endif /* _FBR_FS_H_INCLUDED_ */
