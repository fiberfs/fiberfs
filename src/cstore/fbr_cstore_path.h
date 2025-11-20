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

struct fbr_cstore;
struct fbr_directory;
struct fbr_file;
struct fbr_chunk;
struct fbr_path_name;

size_t fbr_cstore_path_data(struct fbr_cstore *cstore, int metadata, char *buffer,
	size_t buffer_len);
size_t fbr_cstore_path(struct fbr_cstore *cstore, fbr_hash_t hash, int metadata, char *output,
	size_t output_len);
size_t fbr_cstore_path_loader(struct fbr_cstore *cstore, unsigned char dir, int metadata,
	char *buffer, size_t buffer_len);
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

size_t fbr_cstore_s3_url(struct fbr_cstore *cstore, const char *path, char *buffer,
	size_t buffer_len);
size_t fbr_cstore_s3_chunk_url(struct fbr_cstore *cstore, struct fbr_file *file,
	struct fbr_chunk *chunk, char *buffer, size_t buffer_len);
size_t fbr_cstore_s3_index_url(struct fbr_cstore *cstore, struct fbr_directory *directory,
    char *buffer, size_t buffer_len);

#endif /* _FBR_CSTORE_PATH_H_INCLUDED_ */
