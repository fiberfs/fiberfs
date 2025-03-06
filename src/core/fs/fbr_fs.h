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

#include "fiberfs.h"
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
#define FBR_TTL_MAX				INT32_MAX

typedef unsigned long fbr_inode_t;
typedef unsigned int fbr_refcount_t;

typedef void __fbr_attr_printf(1) (fbr_log_f)(const char *fmt, ...);

enum fbr_chunk_state {
	FBR_CHUNK_NONE = 0,
	FBR_CHUNK_EMPTY,
	FBR_CHUNK_LOADING,
	FBR_CHUNK_READY
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

struct fbr_directory_refcounts {
	fbr_refcount_t				in_dindex:1;
	fbr_refcount_t				in_lru:1;
	fbr_refcount_t				fs;
};

RB_HEAD(fbr_filename_tree, fbr_file);
RB_HEAD(fbr_inodes_tree, fbr_file);

struct fbr_directory {
	unsigned int				magic;
#define FBR_DIRECTORY_MAGIC			0xADB900B1

	struct fbr_path				dirname;

	enum fbr_directory_state		state;
	struct fbr_directory_refcounts		refcounts;
	fbr_inode_t				inode;

	pthread_mutex_t				update_lock;
	pthread_cond_t				update;

	unsigned long				version;

	// TODO we need creation date and insertion date
	// creation date will tell us how often to look for updates

	struct fbr_file				*file;
	struct fbr_directory			*stale;

	RB_ENTRY(fbr_directory)			dindex_entry;
	TAILQ_ENTRY(fbr_directory)		lru_entry;
	TAILQ_HEAD(, fbr_file)			file_list;
	struct fbr_filename_tree		filename_tree;

	size_t					file_count;

	unsigned int				expired:1;
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

struct fbr_wbuffer {
	unsigned int				magic;
#define FBR_WBUFFER_MAGIC			0x840F2408
};

struct fbr_fio {
	unsigned int				magic;
#define FBR_FIO_MAGIC				0xC476C0F5

	unsigned int				error:1;
	unsigned int				read_only:1;
	unsigned int				append:1;
	unsigned int				truncate:1;

	struct fbr_file				*file;

	struct fbr_chunk			*_chunks[FBR_BODY_DEFAULT_CHUNKS];
	struct fbr_chunk			**chunks;
	size_t					chunks_pos;
	size_t					chunks_len;

	struct iovec				_iovec[FBR_BODY_DEFAULT_CHUNKS];
	struct iovec				*iovec;
	size_t					iovec_pos;
	size_t					iovec_len;
};

struct fbr_fs_stats {
	unsigned long				directories;
	unsigned long				directories_dindex;
	unsigned long				directories_total;
	unsigned long				directory_refs;

	unsigned long				files;
	unsigned long				files_inodes;
	unsigned long				files_total;
	unsigned long				file_refs;

	unsigned long				requests;
	unsigned long				requests_total;

	unsigned long				fetch_bytes;
	unsigned long				read_bytes;
	unsigned long				write_bytes;
};

struct fbr_fs_config {
	double					dentry_ttl;
};

struct fbr_fs {
	unsigned int				magic;
#define FBR_FS_MAGIC				0x150CC3D2

	struct fbr_inodes			*inodes;
	struct fbr_dindex			*dindex;

	struct fbr_fuse_context			*fuse_ctx;
	struct fbr_directory			*root;

	const struct fbr_store_callbacks	*store;

	struct fbr_fs_config			config;
	struct fbr_fs_stats			stats;

	fbr_log_f				*log;

	unsigned int				shutdown:1;
};

RB_HEAD(fbr_dindex_tree, fbr_directory);

extern const struct fbr_path_name *FBR_DIRNAME_ROOT;
struct fbr_store_callbacks;

typedef void (fbr_inodes_debug_f)(struct fbr_fs *fs, struct fbr_file *file);
typedef void (fbr_dindex_debug_f)(struct fbr_fs *fs, struct fbr_directory *directory);

struct fbr_fs *fbr_fs_alloc(void);
void fbr_fs_set_root(struct fbr_fs *fs, struct fbr_directory *root);
void fbr_fs_release_root(struct fbr_fs *fs, int release_root_inode);
void fbr_fs_set_store(struct fbr_fs *fs, const struct fbr_store_callbacks *store);
void fbr_fs_free(struct fbr_fs *fs);

void fbr_fs_stat_add_count(unsigned long *stat, unsigned long value);
void fbr_fs_stat_add(unsigned long *stat);
void fbr_fs_stat_sub_count(unsigned long *stat, unsigned long value);
void fbr_fs_stat_sub(unsigned long *stat);
double fbr_fs_dentry_ttl(struct fbr_fs *fs);
void __fbr_attr_printf(1) fbr_fs_logger(const char *fmt, ...);

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
void fbr_file_attr(const struct fbr_file *file, struct stat *st);

void fbr_body_init(struct fbr_body *body);
void fbr_body_chunk_add(struct fbr_file *file, fbr_id_t id, size_t offset, size_t length);
void fbr_body_LOCK(struct fbr_body *body);
void fbr_body_UNLOCK(struct fbr_body *body);
void fbr_chunk_take(struct fbr_chunk *chunk);
void fbr_chunk_release(struct fbr_chunk *chunk);
void fbr_body_free(struct fbr_body *body);

RB_PROTOTYPE(fbr_filename_tree, fbr_file, filename_entry, fbr_file_cmp)

struct fbr_directory *fbr_directory_root_alloc(struct fbr_fs *fs);
struct fbr_directory *fbr_directory_alloc(struct fbr_fs *fs, const struct fbr_path_name *dirname,
	fbr_inode_t inode);
int fbr_directory_cmp(const struct fbr_directory *d1, const struct fbr_directory *d2);
void fbr_directory_add_file(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_file *file);
void fbr_directory_set_state(struct fbr_fs *fs, struct fbr_directory *directory,
	enum fbr_directory_state state);
void fbr_directory_wait_ok(struct fbr_fs *fs, struct fbr_directory *directory);
struct fbr_file *fbr_directory_find_file(struct fbr_directory *directory, const char *filename);
void fbr_directory_expire(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_directory *new_directory);

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

struct fbr_fio *fbr_fio_alloc(struct fbr_fs *fs, struct fbr_file *file);
void fbr_fio_pull_chunks(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset,
	size_t size);
void fbr_fio_iovec_gen(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset,
	size_t size);
void fbr_fio_free(struct fbr_fs *fs, struct fbr_fio *fio);

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
#define fbr_fio_ok(fio)					\
{								\
	assert(fio);						\
	assert((fio)->magic == FBR_FIO_MAGIC);			\
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
