/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_PATH_H_INCLUDED_
#define _FBR_CSTORE_PATH_H_INCLUDED_

#include "fiberfs.h"

#define FBR_FIBERFS_NAME			".fiberfs"
#define FBR_FIBERFS_CHUNK			"chunk"
#define FBR_FIBERFS_INDEX			"index"
#define FBR_FIBERFS_ROOT			"root"
#define FBR_FIBERFS_CHUNK_NAME			FBR_FIBERFS_NAME FBR_FIBERFS_CHUNK
#define FBR_FIBERFS_INDEX_NAME			FBR_FIBERFS_NAME FBR_FIBERFS_INDEX
#define FBR_FIBERFS_ROOT_NAME			FBR_FIBERFS_NAME FBR_FIBERFS_ROOT
#define FBR_CSTORE_ROOT_LEN			512
#define FBR_CSTORE_HASHPATH_LEN			(FBR_CSTORE_ROOT_LEN + 128)

/*
struct fbr_cstore_path {
	unsigned int				magic;
#define FBR_CSTORE_PATH_MAGIC			0x7C45C8C8

	size_t					length;
	char					value[FBR_PATH_MAX];
};
*/

struct fbr_cstore_hashpath {
	unsigned int				magic;
#define FBR_CSTORE_HASHPATH_MAGIC		0x2D53AC3F

	size_t					length;
	char					path[FBR_CSTORE_HASHPATH_LEN];
};

struct fbr_cstore_url {
	unsigned int				magic;
#define FBR_CSTORE_URL_MAGIC			0x5F7D9BC1

	size_t					length;
	char					value[FBR_URL_MAX];
};

struct fbr_cstore;
struct fbr_directory;
struct fbr_file;
struct fbr_chunk;
struct fbr_path_name;

void fbr_cstore_hashpath_data(struct fbr_cstore *cstore, int metadata,
	struct fbr_cstore_hashpath *hashpath);
void fbr_cstore_hashpath(struct fbr_cstore *cstore, fbr_hash_t hash, int metadata,
	struct fbr_cstore_hashpath *hashpath);
void fbr_cstore_hashpath_loader(struct fbr_cstore *cstore, unsigned char dir, int metadata,
	struct fbr_cstore_hashpath *hashpath);

size_t fbr_cstore_path_chunk(const struct fbr_file *file, fbr_id_t id, size_t offset, char *buffer,
	size_t buffer_len);
size_t fbr_cstore_path_index(const struct fbr_directory *directory, char *buffer,
	size_t buffer_len);
size_t fbr_cstore_path_root(struct fbr_path_name *dirpath, char *buffer, size_t buffer_len);
size_t fbr_cstore_path_url(struct fbr_cstore *cstore, const char *url, char *output,
	size_t output_len);

fbr_hash_t fbr_cstore_hash_chunk(struct fbr_cstore *cstore, struct fbr_file *file, fbr_id_t id,
	size_t offset);
fbr_hash_t fbr_cstore_hash_index(struct fbr_cstore *cstore, struct fbr_directory *directory);
fbr_hash_t fbr_cstore_hash_root(struct fbr_cstore *cstore, struct fbr_path_name *dirpath);
fbr_hash_t fbr_cstore_hash_url(const char *host, size_t host_len, const char *url, size_t url_len);
fbr_hash_t fbr_cstore_hash_path(struct fbr_cstore *cstore, const char *path, size_t path_len);

void fbr_cstore_s3_url(struct fbr_cstore *cstore, const char *path, struct fbr_cstore_url *url);
void fbr_cstore_s3_chunk_url(struct fbr_cstore *cstore, struct fbr_file *file,
	struct fbr_chunk *chunk, struct fbr_cstore_url *url);
void fbr_cstore_s3_index_url(struct fbr_cstore *cstore, struct fbr_directory *directory,
    struct fbr_cstore_url *url);
void fbr_cstore_s3_url_init(struct fbr_cstore_url *dest, const char *url, size_t url_len);
void fbr_cstore_s3_url_clone(struct fbr_cstore_url *dest, const struct fbr_cstore_url *src);

#define fbr_cstore_hashpath_ok(hpath)		fbr_magic_check(hpath, FBR_CSTORE_HASHPATH_MAGIC)
#define fbr_cstore_url_ok(url)			fbr_magic_check(url, FBR_CSTORE_URL_MAGIC)

#define fbr_cstore_is_path(path)		\
	assert((path) && (path)[0] != '/')

#define fbr_is_path(path)			\
	assert((path) && (path)[0] != '/')

#endif /* _FBR_CSTORE_PATH_H_INCLUDED_ */
