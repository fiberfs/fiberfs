/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_H_INCLUDED_
#define _FBR_CSTORE_H_INCLUDED_

#include <pthread.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "data/queue.h"

#define FBR_CSTORE_ASYNC_QUEUE_MAX		2000
#define FBR_CSTORE_ASYNC_THREAD_MAX		128
#define FBR_CSTORE_ASYNC_THREAD_DEFAULT		4

enum fbr_cstore_op_type {
	FBR_CSOP_NONE = 0,
	FBR_CSOP_TEST,
	FBR_CSOP_WBUFFER_WRITE,
	FBR_CSOP_CHUNK_READ,
	__FBR_CSOP_END
};

struct fbr_cstore_op {
	unsigned				magic;
#define FBR_CSTORE_OP_MAGIC			0x08BDFC3F

	enum fbr_cstore_op_type			type;
	struct fbr_fs				*fs;
	void					*param1;
	void					*param2;
	void					*param3;

	TAILQ_ENTRY(fbr_cstore_op)		entry;
};

typedef void (*fbr_cstore_async_f)(struct fbr_cstore *cstore, struct fbr_cstore_op *op);

struct fbr_cstore_async {
	struct fbr_cstore_op			ops[FBR_CSTORE_ASYNC_QUEUE_MAX];

	size_t					queue_len;
	size_t					queue_max;
	pthread_mutex_t				queue_lock;
	pthread_cond_t				queue_ready;
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

void fbr_cstore_async_init(struct fbr_cstore *cstore);
void fbr_cstore_async_free(struct fbr_cstore *cstore);

int fbr_cstore_async_queue(struct fbr_cstore *cstore, enum fbr_cstore_op_type type,
	struct fbr_fs *fs, void *param1, void *param2, void *param3);
void fbr_cstore_async_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_wbuffer *wbuffer);
void fbr_cstore_async_chunk_read(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_chunk *chunk);
const char *fbr_cstore_async_type(enum fbr_cstore_op_type type);

int fbr_cstore_metadata_read(const char *path, struct fbr_cstore_metadata *metadata);
void fbr_cstore_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_wbuffer *wbuffer);
void fbr_cstore_delete_entry(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry);
void fbr_cstore_chunk_read(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk);
void fbr_cstore_chunk_delete(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk);

#define fbr_cstore_op_ok(op)			fbr_magic_check(op, FBR_CSTORE_OP_MAGIC)

#endif /* _FBR_CSTORE_H_INCLUDED_ */
