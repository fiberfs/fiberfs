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

struct fbr_cstore_backend {
	unsigned			magic;
#define FBR_CSTORE_BACKEND_MAGIC	0x8589C222

	int				port;

	char				*host;
	size_t				host_len;

	unsigned int			tls:1;
};

struct fbr_cstore_s3 {
	struct fbr_cstore_backend	*backend;

	char				*prefix;
	size_t				prefix_len;
};

struct fbr_cstore_cluster {
	struct fbr_cstore_backend	**backends;
	size_t				size;
};

typedef void (*fbr_cstore_s3_put_f)(struct chttp_context *request, void *arg);

struct fbr_cstore;

struct fbr_cstore_backend *fbr_cstore_backend_alloc(const char *host, int port, int tls);
void fbr_cstore_backend_free(struct fbr_cstore_backend *backend);
void fbr_cstore_s3_init(struct fbr_cstore *cstore, const char *host, int port, int tls,
	const char *prefix);
void fbr_cstore_s3_free(struct fbr_cstore *cstore);
void fbr_cstore_cluster_init(struct fbr_cstore_cluster *cluster);
void fbr_cstore_cluster_add(struct fbr_cstore_cluster *cluster, const char *host, int port,
	int tls);
void fbr_cstore_cluster_free(struct fbr_cstore_cluster *cluster);
int fbr_cstore_backend_enabled(struct fbr_cstore *cstore);
struct fbr_cstore_backend *fbr_cstore_backend_get(struct fbr_cstore *cstore, fbr_hash_t hash,
	int retries);

size_t fbr_cstore_s3_splice(struct fbr_cstore *cstore, struct chttp_context *request, int fd,
	size_t size);
void fbr_cstore_s3_send_get(struct fbr_cstore *cstore, struct chttp_context *request,
	const char *file_path, fbr_id_t id, int retries);
void fbr_cstore_s3_send_delete(struct fbr_cstore *cstore, const char *path, fbr_id_t id);
int fbr_cstore_s3_send_finish(struct fbr_cstore *cstore, struct fbr_cstore_op_sync *sync,
	struct chttp_context *request, int error);
void fbr_cstore_s3_wbuffer_send(struct fbr_cstore *cstore, struct chttp_context *request,
	const char *path, struct fbr_wbuffer *wbuffer);
void fbr_cstore_s3_wbuffer_finish(struct fbr_fs *fs, struct fbr_cstore *cstore,
	struct fbr_cstore_op_sync *sync, struct chttp_context *request, struct fbr_wbuffer *wbuffer,
	int error);
void fbr_cstore_s3_chunk_read(struct fbr_fs *fs, struct fbr_cstore *cstore,
	struct fbr_file *file, struct fbr_chunk *chunk);
void fbr_cstore_s3_index_send(struct fbr_cstore *cstore, struct chttp_context *request,
	const char *path, struct fbr_writer *writer, fbr_id_t id);
int fbr_cstore_s3_get(struct fbr_cstore *cstore, fbr_hash_t hash, const char *file_path,
	fbr_id_t id, size_t size, enum fbr_cstore_entry_type type);
int fbr_cstore_s3_root_write(struct fbr_cstore *cstore, struct fbr_writer *root_json,
	const char *root_path, fbr_id_t version, fbr_id_t existing);

#define fbr_cstore_backend_ok(backend)		\
	fbr_magic_check(backend, FBR_CSTORE_BACKEND_MAGIC)

#endif /* _FBR_CSTORE_S3_H_INCLUDED_ */
