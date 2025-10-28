/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_API_H_INCLUDED_
#define _FBR_CSTORE_API_H_INCLUDED_

#include <pthread.h>

#include "fiberfs.h"
#include "fbr_cstore_callback.h"
#include "fbr_cstore_io.h"
#include "fbr_cstore_path.h"
#include "core/fs/fbr_fs.h"
#include "data/queue.h"
#include "data/tree.h"
#include "s3/fbr_cstore_s3.h"
#include "server/fbr_cstore_server.h"

#define FBR_CSTORE_HEAD_COUNT			64
#define FBR_CSTORE_SLAB_SIZE			128
#define FBR_CSTORE_DATA_DIR			"data"
#define FBR_CSTORE_META_DIR			"meta"
#define FBR_CSTORE_LOAD_THREAD_MAX		32
#define FBR_CSTORE_LOAD_THREAD_DEFAULT		4
#define FBR_CSTORE_LOAD_TIME_BUFFER		1.1
#define FBR_CSTORE_RETRIES_DEFAULT		2
#define FBR_CSTORE_ROOT_TTL_DEFAULT		60

enum fbr_cstore_alloc_state {
	FBR_CSTORE_ENTRY_NONE = 0,
	FBR_CSTORE_ENTRY_FREE,
	FBR_CSTORE_ENTRY_USED
};

enum fbr_cstore_state {
	FBR_CSTORE_NULL = 0,
	FBR_CSTORE_NONE,
	FBR_CSTORE_LOADING,
	FBR_CSTORE_OK
};

enum fbr_cstore_loader_state {
	FBR_CSTORE_LOADER_NONE = 0,
	FBR_CSTORE_LOADER_READING,
	FBR_CSTORE_LOADER_DONE
};

struct fbr_cstore_loader {
	enum fbr_cstore_loader_state		state;

	volatile int				stop;
	double					start_time;

	size_t					thread_count;
	size_t					thread_pos;
	size_t					thread_done;
	pthread_t				threads[FBR_CSTORE_LOAD_THREAD_MAX];
};

struct fbr_cstore_entry {
	unsigned				magic;
#define FBR_CSTORE_ENTRY_MAGIC			0xA59C372B

	enum fbr_cstore_alloc_state		alloc;
	enum fbr_cstore_state			state;
	pthread_mutex_t				state_lock;
	pthread_cond_t				state_cond;

	fbr_hash_t				hash;
	size_t					bytes;

	fbr_refcount_t				refcount;
	int					in_lru;

	RB_ENTRY(fbr_cstore_entry)		tree_entry;
	TAILQ_ENTRY(fbr_cstore_entry)		list_entry;
};

struct fbr_cstore_entry_slab {
	struct fbr_cstore_entry			entries[FBR_CSTORE_SLAB_SIZE];
	size_t					count;
	struct fbr_cstore_entry_slab		*next;
};

RB_HEAD(fbr_cstore_tree, fbr_cstore_entry);
TAILQ_HEAD(fbr_cstore_list, fbr_cstore_entry);

struct fbr_cstore_head {
	unsigned				magic;
#define FBR_CSTORE_HEAD_MAGIC			0xA249385F

	struct fbr_cstore_tree			tree;
	struct fbr_cstore_list			lru_list;
	struct fbr_cstore_list			free_list;

	struct fbr_cstore_entry_slab		*slabs;

	pthread_mutex_t				lock;
};

struct fbr_cstore;
typedef void (*fbr_cstore_delete_f)(struct fbr_cstore *cstore,
	struct fbr_cstore_entry *entry);

struct fbr_cstore {
	unsigned				magic;
#define FBR_CSTORE_MAGIC			0xC8747276

	unsigned int				do_free:1;
	unsigned int				cant_splice_in:1;
	unsigned int				cant_splice_out:1;
	unsigned int				delete_cache:1;
	unsigned int				cdn_put:1;
	unsigned int				cdn_delete:1;

	struct fbr_cstore_head			heads[FBR_CSTORE_HEAD_COUNT];

	fbr_cstore_delete_f			delete_f;
	struct fbr_cstore_async			async;
	struct fbr_cstore_loader		loader;
	struct fbr_cstore_tasks			tasks;
	struct fbr_cstore_server		*servers;
	struct fbr_cstore_s3			s3;
	struct fbr_cstore_cluster		cdn;
	struct fbr_cstore_cluster		cluster;

	struct fbr_log				*log;
	char					root[FBR_PATH_MAX];

	unsigned int				retries;
	unsigned long				root_ttl_sec;

	size_t					max_bytes;
	size_t					bytes;
	size_t					entries;
	int					do_lru;

	struct {
		fbr_stats_t			lru_pruned;
		fbr_stats_t			removed;
		fbr_stats_t			loaded;
		fbr_stats_t			lazy_loaded;
		fbr_stats_t			wr_chunks;
		fbr_stats_t			wr_indexes;
		fbr_stats_t			wr_roots;
		fbr_stats_t			wr_chunk_bytes;
		fbr_stats_t			wr_index_bytes;
		fbr_stats_t			wr_root_bytes;
		fbr_stats_t			rd_chunk_bytes;
		fbr_stats_t			workers;
		fbr_stats_t			workers_active;
	} stats;
	};

struct fbr_cstore_metadata {
	char					path[FBR_PATH_MAX];
	fbr_id_t				etag;
	double					timestamp;
	unsigned long				size;
	size_t					offset;
	enum fbr_cstore_entry_type		type;
	int					gzipped;
	int					error;
	char					_context;
};

struct fbr_cstore_config {
	size_t					async_threads;
	size_t					loader_threads;

	int					server;
	char					server_address[128];
	int					server_port;
	int					server_tls;
	size_t					server_workers;
	size_t					server_workers_accept;

	int					delete_cache;
};

extern struct fbr_cstore_config _CSTORE_CONFIG;

struct fbr_cstore *fbr_cstore_alloc(const char *root_path);
void fbr_cstore_init(struct fbr_cstore *cstore, const char *root_path);
void fbr_cstore_max_size(struct fbr_cstore *cstore, size_t max_bytes, int lru);
struct fbr_cstore_entry *fbr_cstore_get(struct fbr_cstore *cstore, fbr_hash_t hash);
struct fbr_cstore_entry *fbr_cstore_insert(struct fbr_cstore *cstore, fbr_hash_t hash,
	size_t bytes, int loading);
int fbr_cstore_set_size(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry, size_t bytes);
int fbr_cstore_set_loading(struct fbr_cstore_entry *entry);
enum fbr_cstore_state fbr_cstore_wait_loading(struct fbr_cstore_entry *entry);
void fbr_cstore_reset_loading(struct fbr_cstore_entry *entry);
void fbr_cstore_set_ok(struct fbr_cstore_entry *entry);
void fbr_cstore_set_error(struct fbr_cstore_entry *entry);
void fbr_cstore_release(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry);
void fbr_cstore_remove(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry);
void fbr_cstore_clear(struct fbr_cstore *cstore);
void fbr_cstore_free(struct fbr_cstore *cstore);

void fbr_cstore_loader_init(struct fbr_cstore *cstore);
void fbr_cstore_loader_free(struct fbr_cstore *cstore);

void fbr_cstore_fuse_register(const char *root_path);
struct fbr_cstore *fbr_cstore_find(void);
size_t fbr_cstore_etag(fbr_id_t id, char *buffer, size_t buffer_len);
const char *fbr_cstore_type_name(enum fbr_cstore_entry_type type);

#define fbr_cstore_ok(cstore)			fbr_magic_check(cstore, FBR_CSTORE_MAGIC)
#define fbr_cstore_head_ok(head)		fbr_magic_check(head, FBR_CSTORE_HEAD_MAGIC)
#define fbr_cstore_entry_ok(entry)		fbr_magic_check(entry, FBR_CSTORE_ENTRY_MAGIC)

#endif /* _FBR_CSTORE_API_H_INCLUDED_ */
