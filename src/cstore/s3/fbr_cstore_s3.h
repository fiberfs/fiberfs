/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_S3_H_INCLUDED_
#define _FBR_CSTORE_S3_H_INCLUDED_

#include <pthread.h>

#include "fiberfs.h"
#include "chttp.h"
#include "core/fs/fbr_fs.h"

struct fbr_cstore_s3 {
	char				*host;
	size_t				host_len;
	char				*prefix;
	size_t				prefix_len;

	int				port;

	unsigned int			enabled:1;
	unsigned int			tls:1;
};

struct fbr_cstore_backend {
	unsigned			magic;
#define FBR_CSTORE_BACKEND_MAGIC	0x8589C222

	int				port;

	unsigned int			tls:1;

	char				host[];
};

struct fbr_cstore_cluster {
	struct fbr_cstore_backend	**backends;
	size_t				size;
};

struct fbr_cstore;

void fbr_cstore_s3_init(struct fbr_cstore *cstore, const char *host, int port, int tls,
	const char *prefix);
void fbr_cstore_s3_free(struct fbr_cstore *cstore);

void fbr_cstore_cluster_init(struct fbr_cstore *cstore);
void fbr_cstore_cluster_add(struct fbr_cstore *cstore, const char *host, int port, int tls);
void fbr_cstore_cluster_free(struct fbr_cstore *cstore);

void fbr_cstore_s3_wbuffer_send(struct fbr_cstore *cstore, struct chttp_context *request,
	const char *path, struct fbr_wbuffer *wbuffer);
pthread_t fbr_cstore_s3_wbuffer_send_async(struct fbr_cstore *cstore,
	struct chttp_context *request, char *path, struct fbr_wbuffer *wbuffer,
	struct fbr_cstore_op *op);
void fbr_cstore_s3_wbuffer_finish(struct fbr_fs *fs, struct fbr_cstore *cstore,
	pthread_t s3_thread, struct chttp_context *request, struct fbr_wbuffer *wbuffer,
	int error);
void fbr_cstore_s3_chunk_read(struct fbr_fs *fs, struct fbr_cstore *cstore,
	struct fbr_file *file, struct fbr_chunk *chunk);
void fbr_cstore_s3_delete(struct fbr_cstore *cstore, const char *path, fbr_id_t id);

#define fbr_cstore_backend_ok(backend)		\
	fbr_magic_check(backend, FBR_CSTORE_BACKEND_MAGIC)

#endif /* _FBR_CSTORE_S3_H_INCLUDED_ */
