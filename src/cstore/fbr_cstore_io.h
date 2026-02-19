/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_IO_H_INCLUDED_
#define _FBR_CSTORE_IO_H_INCLUDED_

#include <pthread.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "data/queue.h"

#define FBR_CSTORE_ASYNC_THREAD_MAX		128
#define FBR_CSTORE_ASYNC_THREAD_DEFAULT		4

#define FBR_ENUM_CSTORE_ENTRY_TYPE 						\
	FBR_ENUM_NAMES(fbr_cstore_entry_type, fbr_cstore_type_name)		\
		FBR_ENUM_VALUES_INIT(FBR_CSTORE_FILE_NONE, "NONE", 0)		\
		FBR_ENUM_VALUES(FBR_CSTORE_FILE_CHUNK, "CHUNK")			\
		FBR_ENUM_VALUES(FBR_CSTORE_FILE_INDEX, "INDEX")			\
		FBR_ENUM_VALUES(FBR_CSTORE_FILE_ROOT, "ROOT")			\
	FBR_ENUM_END("ERROR")

#define FBR_ENUM_CSTORE_OP_TYPE 						\
	FBR_ENUM_NAMES(fbr_cstore_op_type, fbr_cstore_async_type)		\
		FBR_ENUM_VALUES_INIT(FBR_CSOP_NONE, "NONE", 0)			\
		FBR_ENUM_VALUES(FBR_CSOP_TEST, "TEST")				\
		FBR_ENUM_VALUES(FBR_CSOP_WBUFFER_WRITE, "WBUFFER_WRITE")	\
		FBR_ENUM_VALUES(FBR_CSOP_WBUFFER_SEND, "WBUFFER_SEND")		\
		FBR_ENUM_VALUES(FBR_CSOP_CHUNK_READ, "CHUNK_READ")		\
		FBR_ENUM_VALUES(FBR_CSOP_URL_DELETE, "URL_DELETE")		\
		FBR_ENUM_VALUES(FBR_CSOP_INDEX_SEND, "INDEX_SEND")		\
		FBR_ENUM_VALUES(FBR_CSOP_ROOT_WRITE, "ROOT_WRITE")		\
		FBR_ENUM_VALUES(__FBR_CSOP_END, "ERROR")			\
	FBR_ENUM_END("ERROR")

#include "utils/fbr_enum_define.h"
FBR_ENUM_CSTORE_ENTRY_TYPE
FBR_ENUM_CSTORE_OP_TYPE

struct fbr_cstore_op;
struct fbr_cstore_worker;

typedef void (*fbr_cstore_async_f)(struct fbr_cstore *cstore, struct fbr_cstore_op *op);
typedef void (*fbr_cstore_async_done_f)(struct fbr_cstore_op *op,
	struct fbr_cstore_worker *worker);

struct fbr_cstore_op_sync {
	unsigned int				magic;
#define FBR_CSTORE_OP_SYNC_MAGIC		0x64337F38

	int					done;
	int					error;

	enum fbr_cstore_op_type			type;
	unsigned long				async_id;

	pthread_mutex_t				lock;
	pthread_cond_t				cond;
};

struct fbr_cstore_op {
	unsigned int				magic;
#define FBR_CSTORE_OP_MAGIC			0x08BDFC3F

	enum fbr_cstore_op_type			type;

	void					*param0;
	void					*param1;
	void					*param2;
	void					*param3;
	void					*param4;

	fbr_cstore_async_done_f			done_cb;
	void					*done_arg;

	struct fbr_log				*log;
	unsigned long				caller_id;

	TAILQ_ENTRY(fbr_cstore_op)		entry;
};

struct fbr_cstore_async {
	struct fbr_cstore_op			ops[FBR_CSTORE_ASYNC_THREAD_MAX];

	size_t					queue_len;
	pthread_mutex_t				queue_lock;
	pthread_cond_t				todo_ready;
	volatile int				exit;

	pthread_t				threads[FBR_CSTORE_ASYNC_THREAD_MAX];
	size_t					threads_max;
	size_t					threads_running;

	fbr_cstore_async_f			callback;

	TAILQ_HEAD(, fbr_cstore_op)		todo_list;
	TAILQ_HEAD(, fbr_cstore_op)		active_list;
	TAILQ_HEAD(, fbr_cstore_op)		free_list;
};

struct fbr_cstore;
struct fbr_cstore_entry;
struct fbr_cstore_metadata;
struct fbr_cstore_path;
struct fbr_cstore_hashpath;
struct fbr_cstore_url;
struct fbr_writer;
struct chttp_context;

void fbr_cstore_async_init(struct fbr_cstore *cstore);
void fbr_cstore_async_free(struct fbr_cstore *cstore);

int fbr_cstore_async_queue(struct fbr_cstore *cstore, enum fbr_cstore_op_type type,
	void *param0, void *param1, void *param2, void *param3, void *param4,
	fbr_cstore_async_done_f done_cb, void *done_arg);
void fbr_cstore_async_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_wbuffer *wbuffer);
void fbr_cstore_async_chunk_read(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_chunk *chunk);
void fbr_cstore_async_chunk_delete(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_chunk *chunk);
void fbr_cstore_async_wbuffer_send(struct fbr_cstore *cstore, struct chttp_context *http,
	struct fbr_cstore_path *path, struct fbr_wbuffer *wbuffer,
	struct fbr_cstore_op_sync *sync);
void fbr_cstore_async_index_send(struct fbr_cstore *cstore, struct chttp_context *http,
	struct fbr_cstore_path *path, struct fbr_writer *writer, fbr_id_t id,
	struct fbr_cstore_op_sync *sync);
void fbr_cstore_async_index_remove(struct fbr_fs *fs, struct fbr_directory *directory);
void fbr_cstore_async_root_write(struct fbr_cstore *cstore, struct fbr_writer *root_json,
	struct fbr_cstore_path *root_path, fbr_id_t version);

void fbr_cstore_op_sync_init(struct fbr_cstore_op_sync *sync);
void fbr_cstore_op_sync_done(struct fbr_cstore_op *op, struct fbr_cstore_worker *worker);
void fbr_cstore_op_sync_wait(struct fbr_cstore_op_sync *sync);
void fbr_cstore_op_sync_free(struct fbr_cstore_op_sync *sync);

#include "utils/fbr_enum_string_declare.h"
FBR_ENUM_CSTORE_OP_TYPE

int fbr_cstore_metadata_write(struct fbr_cstore_hashpath *hashpath,
	struct fbr_cstore_metadata *metadata);
int fbr_cstore_metadata_read(struct fbr_cstore_hashpath *hashpath,
	struct fbr_cstore_metadata *metadata);
struct fbr_cstore_entry *fbr_cstore_io_get_loading(struct fbr_cstore *cstore, fbr_hash_t hash,
	size_t bytes, struct fbr_cstore_hashpath *hashpath, int remove_on_error);
struct fbr_cstore_entry *fbr_cstore_io_get_ok(struct fbr_cstore *cstore, fbr_hash_t hash);
void fbr_cstore_wbuffer_update(struct fbr_fs *fs, struct fbr_wbuffer *wbuffer,
	enum fbr_wbuffer_state state);
void fbr_cstore_chunk_update(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk,
	enum fbr_chunk_state state);

void fbr_cstore_io_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_wbuffer *wbuffer);
void fbr_cstore_io_delete_entry(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry);
void fbr_cstore_io_delete_url(struct fbr_cstore *cstore, const struct fbr_cstore_url *url,
	fbr_id_t id, enum fbr_cstore_entry_type type);
void fbr_cstore_io_chunk_read(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk);
int fbr_cstore_io_index_write(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_writer *writer);
int fbr_cstore_io_index_read(struct fbr_fs *fs, struct fbr_directory *directory);
void fbr_cstore_io_index_remove(struct fbr_fs *fs, struct fbr_directory *directory);
int fbr_cstore_io_index_delete(struct fbr_fs *fs, struct fbr_directory *directory);
int fbr_cstore_io_root_write(struct fbr_cstore *cstore, struct fbr_writer *root_json,
	struct fbr_cstore_path *root_path, fbr_id_t version, fbr_id_t existing, int enforce);
fbr_id_t fbr_cstore_io_root_read(struct fbr_cstore *cstore, struct fbr_cstore_path *root_path);
int fbr_cstore_io_root_remove(struct fbr_fs *fs, struct fbr_directory *directory);

enum fbr_cstore_entry_type fbr_cstore_url_parse(const char *url, size_t url_len, const char *etag,
	size_t etag_len, size_t *offset);
void fbr_cstore_url_write(struct fbr_cstore_worker *worker, struct chttp_context *http);
void fbr_cstore_url_read(struct fbr_cstore_worker *worker, struct chttp_context *http);
void fbr_cstore_url_delete(struct fbr_cstore_worker *worker, struct chttp_context *http);

#define fbr_cstore_op_ok(op)			fbr_magic_check(op, FBR_CSTORE_OP_MAGIC)
#define fbr_cstore_op_sync_ok(sync)		fbr_magic_check(sync, FBR_CSTORE_OP_SYNC_MAGIC)

#endif /* _FBR_CSTORE_IO_H_INCLUDED_ */
