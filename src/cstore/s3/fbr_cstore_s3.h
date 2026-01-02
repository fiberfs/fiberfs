/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_S3_H_INCLUDED_
#define _FBR_CSTORE_S3_H_INCLUDED_

#include <pthread.h>
#include <time.h>

#include "fiberfs.h"
#include "chttp.h"
#include "core/fs/fbr_fs.h"

// TODO is this a good size?
#define FBR_CSTORE_IO_SIZE		(1024 * 16)
#define FBR_CSTORE_CHTTP_SIZE		4096

enum fbr_cstore_route {
	FBR_CSTORE_ROUTE_NONE = 0,
	FBR_CSTORE_ROUTE_CLUSTER,
	FBR_CSTORE_ROUTE_CDN,
	FBR_CSTORE_ROUTE_S3
};

struct fbr_cstore_backend {
	unsigned int			magic;
#define FBR_CSTORE_BACKEND_MAGIC	0x8589C222

	int				port;

	char				*host;
	size_t				host_len;

	unsigned int			tls:1;
	unsigned int			offline:1;

	fbr_hash_t			hash;
};

struct fbr_cstore_s3 {
	struct fbr_cstore_backend	*backend;

	char				*prefix;
	size_t				prefix_len;

	char				*region;
	size_t				region_len;
	char				*access_key;
	size_t				access_key_len;
	char				*secret_key;
	size_t				secret_key_len;
};

struct fbr_cstore_cluster {
	struct fbr_cstore_backend	**backends;
	size_t				size;
};

typedef void (*fbr_cstore_s3_put_f)(struct chttp_context *http, void *arg);

struct fbr_cstore;

void fbr_cstore_s3_init(struct fbr_cstore *cstore, const char *host, int port, int tls,
	const char *prefix, const char *region, const char *access_key, const char *secret_key);
void fbr_cstore_s3_free(struct fbr_cstore *cstore);
void fbr_cstore_cluster_init(struct fbr_cstore_cluster *cluster);
void fbr_cstore_cluster_add(struct fbr_cstore_cluster *cluster, const char *host, int port,
	int tls);
void fbr_cstore_cluster_free(struct fbr_cstore_cluster *cluster);
int fbr_cstore_backend_enabled(struct fbr_cstore *cstore);
struct fbr_cstore_backend *fbr_cstore_backend_get(struct fbr_cstore *cstore, fbr_hash_t hash,
	enum fbr_cstore_route route, int retries, int cdn_ok);

size_t fbr_cstore_s3_splice_out(struct fbr_cstore *cstore, struct chttp_addr *addr, int fd_in,
	size_t size);
size_t fbr_cstore_s3_splice_in(struct fbr_cstore *cstore, struct chttp_context *http, int fd_out,
	size_t size);
void fbr_cstore_s3_send_get(struct fbr_cstore *cstore, struct chttp_context *http,
	struct fbr_cstore_path *file_path, fbr_id_t id, enum fbr_cstore_route route);
void fbr_s3_send_put(struct fbr_cstore *cstore, struct chttp_context *http,
	enum fbr_cstore_entry_type type, struct fbr_cstore_path *path, size_t length,
	fbr_id_t etag, fbr_id_t existing, int gzip, fbr_cstore_s3_put_f data_cb, void *put_arg,
	enum fbr_cstore_route route);
int fbr_cstore_s3_send_finish(struct fbr_cstore *cstore, struct fbr_cstore_op_sync *sync,
	struct chttp_context *http, int error);
int fbr_cstore_s3_get_write(struct fbr_cstore *cstore, fbr_hash_t hash,
	struct fbr_cstore_path *file_path, fbr_id_t id, size_t size,
	enum fbr_cstore_entry_type type, enum fbr_cstore_route route);
int fbr_cstore_s3_send_delete(struct fbr_cstore *cstore, const struct fbr_cstore_url *url,
	fbr_id_t id, enum fbr_cstore_route route);
void fbr_cstore_s3_wbuffer_send(struct fbr_cstore *cstore, struct chttp_context *http,
	struct fbr_cstore_path *path, struct fbr_wbuffer *wbuffer);
void fbr_cstore_s3_wbuffer_finish(struct fbr_fs *fs, struct fbr_cstore *cstore,
	struct fbr_cstore_op_sync *sync, struct chttp_context *http, struct fbr_wbuffer *wbuffer,
	int error);
void fbr_cstore_s3_chunk_read(struct fbr_fs *fs, struct fbr_cstore *cstore,
	struct fbr_file *file, struct fbr_chunk *chunk);
void fbr_cstore_s3_index_send(struct fbr_cstore *cstore, struct chttp_context *http,
	struct fbr_cstore_path *path, struct fbr_writer *writer, fbr_id_t id);
int fbr_cstore_s3_root_put(struct fbr_cstore *cstore, struct fbr_writer *root_json,
	struct fbr_cstore_path *root_path, fbr_id_t version, fbr_id_t existing,
	enum fbr_cstore_route route);
fbr_id_t fbr_cstore_s3_root_get(struct fbr_fs *fs, struct fbr_cstore *cstore,
	struct fbr_cstore_path *root_path, int attempts);

typedef size_t (*fbr_cstore_s3_hash_f)(void *priv, void *hash, size_t hash_len);

size_t fbr_cstore_s3_hash_none(void *priv, void *hash, size_t hash_len);
void fbr_cstore_s3_autosign(struct fbr_cstore *cstore, struct chttp_context *http,
	fbr_cstore_s3_hash_f hash_cb, void *hash_priv);
void fbr_cstore_s3_sign(struct chttp_context *http, time_t sign_time, int skip_content_hash,
	fbr_cstore_s3_hash_f hash_cb, void *hash_priv, const char *host, size_t host_len,
	const char *region, size_t region_len, const char *access_key, size_t access_key_len,
	const char *secret_key);
int fbr_cstore_s3_validate(struct fbr_cstore *cstore, struct chttp_context *http);

#define fbr_cstore_backend_ok(backend)		\
	fbr_magic_check(backend, FBR_CSTORE_BACKEND_MAGIC)

#endif /* _FBR_CSTORE_S3_H_INCLUDED_ */
