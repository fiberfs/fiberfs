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
#include "fbr_path.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/request/fbr_request.h"
#include "data/queue.h"
#include "data/tree.h"

#define FBR_INODE_ROOT				FUSE_ROOT_ID
#define FBR_READDIR_SIZE			4096
#define FBR_BODY_DEFAULT_CHUNKS			4
#define FBR_BODY_SLAB_DEFAULT_CHUNKS		32
#define FBR_FILE_DEFAULT_PTRS			32
#define FBR_TTL_MAX				INT32_MAX

enum fbr_chunk_state {
	FBR_CHUNK_NONE = 0,
	FBR_CHUNK_EMPTY,
	FBR_CHUNK_LOADING,
	FBR_CHUNK_READY,
	FBR_CHUNK_SPLICED,
	FBR_CHUNK_WBUFFER
};

struct fbr_chunk {
	unsigned int				magic;
#define FBR_CHUNK_MAGIC				0xA8E5D947

	enum fbr_chunk_state			state;

	unsigned int				fd_splice_ok:1;
	unsigned int				do_free:1;

	fbr_id_t				id;

	size_t					offset;
	size_t					length;
	size_t					partial;

	fbr_refcount_t				refcount;

	uint8_t					*data;

	void					*chttp_splice;
	struct fbr_chunk			*next;
};

struct fbr_chunk_slab {
	unsigned int				magic;
#define FBR_CHUNK_SLAB_MAGIC			0x68469049

	unsigned int				length;

	struct fbr_chunk_slab			*next;
	struct fbr_chunk			chunks[];
};

struct fbr_chunk_list {
	unsigned int				magic;
#define FBR_CHUNK_LIST_MAGIC			0x8E1FB2D4

	unsigned int				capacity;
	unsigned int				length;

	struct fbr_chunk			*list[];
};

struct fbr_chunk_vector {
	unsigned int				magic;
#define FBR_CHUNK_VECTOR_MAGIC			0xDDB1156D

	struct fbr_chunk_list			*chunks;
	struct fuse_bufvec			*bufvec;
	size_t					offset;
	size_t					size;
};

struct fbr_body {
	pthread_mutex_t				lock;
	pthread_cond_t				update;

	struct {
		struct fbr_chunk		chunks[FBR_BODY_DEFAULT_CHUNKS];
		struct fbr_chunk_slab		*next;
	}  slabhead;

	struct fbr_chunk			*chunks;
	struct fbr_chunk			*chunk_last;
};

struct fbr_file_refcounts {
	fbr_refcount_t				dindex;
	fbr_refcount_t				inode;
};

struct fbr_file_ptr {
	struct fbr_file				*file;

	TAILQ_ENTRY(fbr_file)			file_entry;
	RB_ENTRY(fbr_file)			filename_entry;
};

struct fbr_file_ptr_slab {
	unsigned int				magic;
#define FBR_FILE_PTR_SLAB_MAGIC			0xB9477AD7

	unsigned int				size;
	struct fbr_file_ptr_slab		*next;
	struct fbr_file_ptr			ptrs[];
};

enum fbr_file_state {
	FBR_FILE_INIT = 0,
	FBR_FILE_OK,
	FBR_FILE_EXPIRED
};

struct fbr_file {
	unsigned int				magic;
#define FBR_FILE_MAGIC				0x8F97F917

	enum fbr_file_state			state;

	struct fbr_path				path;

	struct fbr_file_refcounts		refcounts;
	pthread_mutex_t				refcount_lock;

	fbr_inode_t				inode;
	fbr_inode_t				parent_inode;
	unsigned long				generation;

	unsigned long				size;
	mode_t					mode;
	uid_t					uid;
	gid_t					gid;

	TAILQ_ENTRY(fbr_file)			file_entry;
	RB_ENTRY(fbr_file)			filename_entry;
	RB_ENTRY(fbr_file)			inode_entry;

	struct fbr_body				body;
};

enum fbr_directory_state {
	FBR_DIRSTATE_NONE = 0,
	FBR_DIRSTATE_LOADING,
	FBR_DIRSTATE_OK,
	FBR_DIRSTATE_ERROR
};

struct fbr_directory_refcounts {
	fbr_refcount_t				in_dindex;
	fbr_refcount_t				in_lru;
	fbr_refcount_t				fs;
};

RB_HEAD(fbr_filename_tree, fbr_file);
RB_HEAD(fbr_inodes_tree, fbr_file);

struct fbr_directory {
	unsigned int				magic;
#define FBR_DIRECTORY_MAGIC			0xADB900B1

	enum fbr_directory_state		state;
	struct fbr_directory_refcounts		refcounts;
	fbr_inode_t				inode;

	pthread_cond_t				update;

	struct fbr_path_shared			*path;

	double					creation;
	fbr_id_t				version;
	unsigned long				generation;

	struct fbr_file				*file;
	struct fbr_directory			*previous;
	struct fbr_directory			*next;

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

	unsigned int				read_dot:1;
	unsigned int				read_dotdot:1;
	unsigned int				end:1;

	struct fbr_directory			*directory;
	struct fbr_file				*position;
};

enum fbr_wbuffer_state {
	FBR_WBUFFER_NONE = 0,
	FBR_WBUFFER_WRITING,
	FBR_WBUFFER_READY,
	FBR_WBUFFER_SYNC,
	FBR_WBUFFER_DONE,
	FBR_WBUFFER_ERROR
};

struct fbr_wbuffer {
	unsigned int				magic;
#define FBR_WBUFFER_MAGIC			0x840F2408

	enum fbr_wbuffer_state			state;

	uint8_t					*buffer;
	size_t					offset;
	size_t					size;
	size_t					end;

	fbr_id_t				id;

	struct fbr_fio				*fio;
	struct fbr_chunk			*chunk;
	struct fbr_wbuffer			*next;
};

struct fbr_fio {
	unsigned int				magic;
#define FBR_FIO_MAGIC				0xC476C0F5

	unsigned int				error:1;
	unsigned int				read_only:1;
	unsigned int				append:1;
	unsigned int				truncate:1;

	fbr_refcount_t				refcount;

	fbr_id_t				id;

	struct fbr_file				*file;
	struct fbr_chunk_list			*floating;
	struct fbr_wbuffer			*wbuffers;

	pthread_mutex_t				wbuffer_lock;
	pthread_cond_t				wbuffer_update;
};

struct fbr_fs_stats {
	fbr_stats_t				directories;
	fbr_stats_t				directories_dindex;
	fbr_stats_t				directories_total;
	fbr_stats_t				directory_refs;

	fbr_stats_t				files;
	fbr_stats_t				files_inodes;
	fbr_stats_t				files_total;
	fbr_stats_t				file_refs;

	fbr_stats_t				requests_active;
	fbr_stats_t				requests_alloc;
	fbr_stats_t				requests_freed;
	fbr_stats_t				requests_recycled;
	fbr_stats_t				requests_pooled;

	fbr_stats_t				fetch_bytes;
	fbr_stats_t				read_bytes;
	fbr_stats_t				write_bytes;
	fbr_stats_t				store_bytes;

	fbr_stats_t				flushes;
};

struct fbr_fs_config {
	double					dentry_ttl;
};

struct fbr_fs {
	unsigned int				magic;
#define FBR_FS_MAGIC				0x150CC3D2

	unsigned int				shutdown:1;

	struct fbr_inodes			*inodes;
	struct fbr_dindex			*dindex;

	struct fbr_fuse_context			*fuse_ctx;
	struct fbr_file				*root_file;

	pthread_mutex_t				lock;

	const struct fbr_store_callbacks	*store;

	struct fbr_fs_config			config;
	struct fbr_fs_stats			stats;

	fbr_log_f				*logger;
};

RB_HEAD(fbr_dindex_tree, fbr_directory);

extern const struct fbr_path_name *FBR_DIRNAME_ROOT;
struct fbr_store_callbacks;
struct fbr_dindex_dirhead;

typedef void (fbr_inodes_debug_f)(struct fbr_fs *fs, struct fbr_file *file);
typedef void (fbr_dindex_debug_f)(struct fbr_fs *fs, struct fbr_directory *directory);

struct fbr_fs *fbr_fs_alloc(void);
void fbr_fs_LOCK(struct fbr_fs *fs);
void fbr_fs_UNLOCK(struct fbr_fs *fs);
void fbr_fs_release_all(struct fbr_fs *fs, int release_root_inode);
void fbr_fs_set_store(struct fbr_fs *fs, const struct fbr_store_callbacks *store);
void fbr_fs_free(struct fbr_fs *fs);

void fbr_fs_stat_add_count(fbr_stats_t *stat, fbr_stats_t value);
void fbr_fs_stat_add(fbr_stats_t *stat);
void fbr_fs_stat_sub_count(fbr_stats_t *stat, fbr_stats_t value);
void fbr_fs_stat_sub(fbr_stats_t *stat);
double fbr_fs_dentry_ttl(struct fbr_fs *fs);
void __fbr_attr_printf(1) fbr_fs_logger(const char *fmt, ...);
size_t fbr_fs_chunk_size(size_t offset);

fbr_id_t fbr_id_gen(void);
size_t fbr_id_string(fbr_id_t value, char *buffer, size_t buffer_len);

void fbr_inodes_alloc(struct fbr_fs *fs);
fbr_inode_t fbr_inode_gen(struct fbr_fs *fs);
void fbr_inode_add(struct fbr_fs *fs, struct fbr_file *file);
struct fbr_file *fbr_inode_take(struct fbr_fs *fs, fbr_inode_t inode);
void fbr_inode_release(struct fbr_fs *fs, struct fbr_file **file_ref);
void fbr_inode_forget(struct fbr_fs *fs, fbr_inode_t inode, fbr_refcount_t refs);
void fbr_inodes_debug(struct fbr_fs *fs, fbr_inodes_debug_f *callback);
void fbr_inodes_free_all(struct fbr_fs *fs);

struct fbr_file *fbr_file_alloc(struct fbr_fs *fs, struct fbr_directory *parent,
	const struct fbr_path_name *filename);
struct fbr_file * fbr_file_alloc_new(struct fbr_fs *fs, struct fbr_directory *parent,
	const struct fbr_path_name *filename);
int fbr_file_cmp(const struct fbr_file *f1, const struct fbr_file *f2);
int fbr_file_inode_cmp(const struct fbr_file *f1, const struct fbr_file *f2);
void fbr_file_ref_dindex(struct fbr_fs *fs, struct fbr_file *file);
void fbr_file_release_dindex(struct fbr_fs *fs, struct fbr_file **file_ref);
void fbr_file_ref_inode(struct fbr_fs *fs, struct fbr_file *file);
void fbr_file_release_inode_lock(struct fbr_fs *fs, struct fbr_file *file);
void fbr_file_forget_inode_lock(struct fbr_fs *fs, struct fbr_file *file, fbr_refcount_t refs);
void fbr_file_free(struct fbr_fs *fs, struct fbr_file *file);
struct fbr_file_ptr_slab *fbr_file_ptr_slab_alloc(void);
void fbr_file_ptr_slab_free(struct fbr_file_ptr_slab *ptr_slab);
void fbr_file_attr(const struct fbr_file *file, struct stat *st);

void fbr_chunk_take(struct fbr_chunk *chunk);
void fbr_chunk_release(struct fbr_chunk *chunk);
int fbr_chunk_in_offset(struct fbr_chunk *chunk, size_t offset, size_t size);
const char *fbr_chunk_state(enum fbr_chunk_state state);

struct fbr_chunk_list *fbr_chunk_list_alloc(void);
struct fbr_chunk_list *fbr_chunk_list_expand(struct fbr_chunk_list *chunks);
void fbr_chunk_list_debug(struct fbr_fs *fs, struct fbr_chunk_list *chunks, const char *name);
struct fbr_chunk_list *fbr_chunk_list_add(struct fbr_chunk_list *chunks,
	struct fbr_chunk *chunk);
int fbr_chunk_list_contains(struct fbr_chunk_list *chunks, struct fbr_chunk *chunk);
struct fbr_chunk *fbr_chunk_list_find(struct fbr_chunk_list *chunks, size_t offset);
struct fbr_chunk *fbr_chunk_list_next(struct fbr_chunk_list *chunks, size_t offset);
struct fbr_chunk_list *fbr_chunk_list_file(struct fbr_file *file, size_t offset, size_t size,
	struct fbr_chunk_list **removed);
void fbr_chunk_list_free(struct fbr_chunk_list *chunks);

void fbr_body_init(struct fbr_body *body);
struct fbr_chunk *fbr_body_chunk_add(struct fbr_file *file, fbr_id_t id, size_t offset,
	size_t length);
void fbr_body_LOCK(struct fbr_fs *fs, struct fbr_body *body);
void fbr_body_UNLOCK(struct fbr_body *body);
void fbr_body_debug(struct fbr_fs *fs, struct fbr_file *file);
void fbr_body_free(struct fbr_body *body);

RB_PROTOTYPE(fbr_filename_tree, fbr_file, filename_entry, fbr_file_cmp)

struct fbr_directory *fbr_directory_root_alloc(struct fbr_fs *fs);
struct fbr_directory *fbr_directory_alloc(struct fbr_fs *fs, const struct fbr_path_name *dirname,
	fbr_inode_t inode);
void fbr_directory_free(struct fbr_fs *fs, struct fbr_directory *directory);
void fbr_directory_name(struct fbr_directory *directory, struct fbr_path_name *result);
int fbr_directory_cmp(const struct fbr_directory *d1, const struct fbr_directory *d2);
int fbr_directory_new_cmp(const struct fbr_directory *left,
	const struct fbr_directory *right);
void fbr_directory_add_file(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_file *file);
struct fbr_file *fbr_directory_find_file(struct fbr_directory *directory, const char *filename,
	size_t filename_len);
struct fbr_directory *fbr_directory_clone(struct fbr_fs *fs, struct fbr_directory *source);

void fbr_dindex_alloc(struct fbr_fs *fs);
void fbr_directory_set_state(struct fbr_fs *fs, struct fbr_directory *directory,
	enum fbr_directory_state state);
void fbr_directory_wait_ok(struct fbr_fs *fs, struct fbr_directory *directory);
struct fbr_directory *fbr_dindex_add(struct fbr_fs *fs, struct fbr_directory *directory);
struct fbr_directory *fbr_dindex_take(struct fbr_fs *fs, const struct fbr_path_name *dirname,
	int wait_for_new);
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
void fbr_fio_take(struct fbr_fio *fio);
struct fbr_chunk_vector *fbr_fio_vector_gen(struct fbr_fs *fs, struct fbr_fio *fio,
	size_t offset, size_t size);
void fbr_chunk_update(struct fbr_fs *fs, struct fbr_body *body, struct fbr_chunk *chunk,
	enum fbr_chunk_state state);
void fbr_fio_vector_free(struct fbr_fs *fs, struct fbr_fio *fio,
	struct fbr_chunk_vector *vector);
void fbr_fio_release(struct fbr_fs *fs, struct fbr_fio *fio);

void fbr_wbuffer_init(struct fbr_fio *fio);
void fbr_wbuffer_write(struct fbr_fs *fs, struct fbr_fio *fio, size_t offset,
	const char *buf, size_t size);
void fbr_wbuffer_update(struct fbr_fs *fs, struct fbr_wbuffer *wbuffer,
	enum fbr_wbuffer_state state);
int fbr_wbuffer_flush(struct fbr_fs *fs, struct fbr_fio *fio);
void fbr_wbuffer_free(struct fbr_fs *fs, struct fbr_fio *fio);

#define fbr_fs_ok(fs)			fbr_magic_check(fs, FBR_FS_MAGIC)
#define fbr_file_ok(file)		fbr_magic_check(file, FBR_FILE_MAGIC)
#define fbr_file_ptr_slab_ok(slab)	fbr_magic_check(slab, FBR_FILE_PTR_SLAB_MAGIC);
#define fbr_directory_ok(dir)		fbr_magic_check(dir, FBR_DIRECTORY_MAGIC)
#define fbr_dreader_ok(dreader)		fbr_magic_check(dreader, FBR_DREADER_MAGIC)
#define fbr_fio_ok(fio)			fbr_magic_check(fio, FBR_FIO_MAGIC)
#define fbr_wbuffer_ok(wbuffer)		fbr_magic_check(wbuffer, FBR_WBUFFER_MAGIC)
#define fbr_chunk_ok(chunk)		fbr_magic_check(chunk, FBR_CHUNK_MAGIC)
#define fbr_chunk_slab_ok(slab)		fbr_magic_check(slab, FBR_CHUNK_SLAB_MAGIC)
#define fbr_chunk_list_ok(list)		fbr_magic_check(list, FBR_CHUNK_LIST_MAGIC)
#define fbr_chunk_vector_ok(vector)	fbr_magic_check(vector, FBR_CHUNK_VECTOR_MAGIC)

#define fbr_fs_int64(obj)					\
	((uint64_t)(obj))
#define log(fmt, ...)						\
	logger(fmt "\n", ##__VA_ARGS__)

#endif /* _FBR_FS_H_INCLUDED_ */
