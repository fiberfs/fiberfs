/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "core/fs/fbr_fs.h"
#include "utils/fbr_xxhash.h"

static inline const char *
_cstore_sub_path(int metadata)
{
	if (metadata) {
		return FBR_CSTORE_META_DIR;
	}

	return FBR_CSTORE_DATA_DIR;
}

size_t
fbr_cstore_path_data(struct fbr_cstore *cstore, int metadata, char *buffer, size_t buffer_len)
{
	fbr_cstore_ok(cstore);
	assert_dev(buffer);
	assert_dev(buffer_len);

	const char *sub_path = _cstore_sub_path(metadata);
	size_t ret = fbr_snprintf(buffer, buffer_len, "%s/%s/", cstore->root, sub_path);

	return ret;
}

size_t
fbr_cstore_path(struct fbr_cstore *cstore, fbr_hash_t hash, int metadata, char *buffer,
    size_t buffer_len)
{
	fbr_cstore_ok(cstore);
	assert(buffer);
	assert(buffer_len);

	char hash_str[FBR_HASH_SLEN];
	fbr_bin2hex(&hash, sizeof(hash), hash_str, sizeof(hash_str));
	assert_dev(strlen(hash_str) > 4);

	const char *sub_path = _cstore_sub_path(metadata);

	size_t ret = fbr_snprintf(buffer, buffer_len, "%s/%s/%.2s/%.2s/%s",
		cstore->root,
		sub_path,
		hash_str,
		hash_str + 2,
		hash_str + 4);

	return ret;
}

size_t
fbr_cstore_path_loader(struct fbr_cstore *cstore, unsigned char dir, int metadata, char *buffer,
    size_t buffer_len)
{
	fbr_cstore_ok(cstore);
	assert(buffer);
	assert(buffer_len);

	char hash_str[3];
	size_t hash_len = fbr_bin2hex(&dir, sizeof(dir), hash_str, sizeof(hash_str));
	assert_dev(hash_len + 1 == sizeof(hash_str));

	const char *sub_path = _cstore_sub_path(metadata);

	size_t ret = fbr_snprintf(buffer, buffer_len, "%s/%s/%s",
		cstore->root,
		sub_path,
		hash_str);

	return ret;
}

size_t
fbr_cstore_path_chunk(struct fbr_cstore *cstore, const struct fbr_file *file, fbr_id_t id,
    size_t offset, int metadata, char *buffer, size_t buffer_len)
{
	fbr_file_ok(file);
	assert(id);
	assert(buffer);
	assert(buffer_len);

	char filebuf[FBR_PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, filebuf, sizeof(filebuf));

	char chunk_id[FBR_ID_STRING_MAX];
	fbr_id_string(id, chunk_id, sizeof(chunk_id));

	size_t ret = 0;

	if (cstore) {
		ret = fbr_cstore_path_data(cstore, metadata, buffer, buffer_len);
	}

	ret += fbr_snprintf(buffer + ret, buffer_len - ret, "%s.%s.%zu",
		filepath.name,
		chunk_id,
		offset);
	assert(ret < buffer_len);

	return ret;
}

size_t
fbr_cstore_path_index(struct fbr_cstore *cstore, const struct fbr_directory *directory,
    int metadata, char *buffer, size_t buffer_len)
{
	fbr_directory_ok(directory);
	assert(buffer);
	assert(buffer_len);

	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);

	char version[FBR_ID_STRING_MAX];
	fbr_id_string(directory->version, version, sizeof(version));

	size_t ret = 0;

	if (cstore) {
		ret = fbr_cstore_path_data(cstore, metadata, buffer, buffer_len);
	}

	char *root_sep = "";
	if (dirpath.length) {
		root_sep = "/";
	}

	ret += fbr_snprintf(buffer + ret, buffer_len - ret, "%s%s.fiberfsindex.%s",
		dirpath.name,
		root_sep,
		version);
	assert(ret < buffer_len);

	return ret;
}

size_t
fbr_cstore_path_root(struct fbr_cstore *cstore, struct fbr_path_name *dirpath, int metadata,
    char *buffer, size_t buffer_len)
{
	assert(dirpath);
	assert(buffer);
	assert(buffer_len);

	size_t ret = 0;

	if (cstore) {
		ret = fbr_cstore_path_data(cstore, metadata, buffer, buffer_len);
	}

	char *root_sep = "";
	if (dirpath->length) {
		root_sep = "/";
	}

	ret += fbr_snprintf(buffer + ret, buffer_len - ret, "%s%s.fiberfsroot",
		dirpath->name,
		root_sep);
	assert(ret < buffer_len);

	return ret;
}

static void
_hash_s3(XXH3_state_t *hash, struct fbr_cstore *cstore)
{
	assert_dev(hash);
	assert_dev(cstore);

	// host + NULL + [/prefix] + /

	if (!cstore->s3.enabled) {
		XXH3_64bits_update(hash, "", 1);
		XXH3_64bits_update(hash, "/", 1);
		return;
	}

	assert(cstore->s3.host);
	size_t len = strlen(cstore->s3.host);
	XXH3_64bits_update(hash, cstore->s3.host, len + 1);

	if (cstore->s3.prefix) {
		assert_dev(cstore->s3.prefix_len);
		assert_dev(cstore->s3.prefix[cstore->s3.prefix_len - 1] != '/');
		XXH3_64bits_update(hash, cstore->s3.prefix, cstore->s3.prefix_len);
	}

	XXH3_64bits_update(hash, "/", 1);
}

/*
static void
_hash_external(XXH3_state_t *hash, fbr_id_t id)
{
	assert_dev(hash);
	assert_dev(id);

	char buffer[FBR_ID_STRING_MAX];
	size_t buffer_len = fbr_id_string(id, buffer, sizeof(buffer));
	assert_dev(buffer_len < sizeof(buffer));

	// TODO path?

	XXH3_64bits_update(hash, buffer, buffer_len + 1);
}

static void
_hash_range(XXH3_state_t *hash, size_t offset, size_t length)
{
	assert_dev(hash);
	assert_dev(length);

	(void)offset;

	fbr_ABORT("TODO");
}
*/

fbr_hash_t
fbr_cstore_hash_chunk(struct fbr_cstore *cstore, struct fbr_file *file, fbr_id_t id,
    size_t offset)
{
	fbr_cstore_ok(cstore);
	fbr_file_ok(file);
	assert(id);

	XXH3_state_t hash;
	XXH3_INITSTATE(&hash);
	XXH3_64bits_reset(&hash);

	_hash_s3(&hash, cstore);

	char buffer[FBR_PATH_MAX];
	size_t len = fbr_cstore_path_chunk(NULL, file, id, offset, 0, buffer, sizeof(buffer));
	XXH3_64bits_update(&hash, buffer, len + 1);

	XXH64_hash_t result = XXH3_64bits_digest(&hash);
	static_ASSERT(sizeof(result) == sizeof(fbr_hash_t));

	// TODO external

	return (fbr_hash_t)result;
}

fbr_hash_t
fbr_cstore_hash_index(struct fbr_cstore *cstore, struct fbr_directory *directory)
{
	fbr_cstore_ok(cstore);
	fbr_directory_ok(directory);

	XXH3_state_t hash;
	XXH3_INITSTATE(&hash);
	XXH3_64bits_reset(&hash);

	_hash_s3(&hash, cstore);

	char buffer[FBR_PATH_MAX];
	size_t len = fbr_cstore_path_index(NULL, directory, 0, buffer, sizeof(buffer));
	XXH3_64bits_update(&hash, buffer, len + 1);

	XXH64_hash_t result = XXH3_64bits_digest(&hash);
	static_ASSERT(sizeof(result) == sizeof(fbr_hash_t));

	return (fbr_hash_t)result;
}

fbr_hash_t
fbr_cstore_hash_root(struct fbr_cstore *cstore, struct fbr_path_name *dirpath)
{
	fbr_cstore_ok(cstore);
	assert(dirpath);

	XXH3_state_t hash;
	XXH3_INITSTATE(&hash);
	XXH3_64bits_reset(&hash);

	_hash_s3(&hash, cstore);

	char buffer[FBR_PATH_MAX];
	size_t len = fbr_cstore_path_root(NULL, dirpath, 0, buffer, sizeof(buffer));
	XXH3_64bits_update(&hash, buffer, len + 1);

	XXH64_hash_t result = XXH3_64bits_digest(&hash);
	static_ASSERT(sizeof(result) == sizeof(fbr_hash_t));

	return (fbr_hash_t)result;
}

fbr_hash_t
fbr_cstore_hash_url(const char *host, size_t host_len, const char *url, size_t url_len)
{
	assert(url);
	assert(url_len);

	XXH3_state_t hash;
	XXH3_INITSTATE(&hash);
	XXH3_64bits_reset(&hash);

	if (host_len) {
		XXH3_64bits_update(&hash, host, host_len);
	}
	XXH3_64bits_update(&hash, "", 1);
	XXH3_64bits_update(&hash, url, url_len);
	XXH3_64bits_update(&hash, "", 1);

	XXH64_hash_t result = XXH3_64bits_digest(&hash);
	static_ASSERT(sizeof(result) == sizeof(fbr_hash_t));

	// TODO external

	return (fbr_hash_t)result;
}

size_t
fbr_cstore_s3_url(struct fbr_cstore *cstore, const char *path, char *buffer, size_t buffer_len)
{
	fbr_cstore_ok(cstore);
	assert(path);
	assert(buffer);
	assert(buffer_len);

	const char *prefix = cstore->s3.prefix;
	if (!prefix || !cstore->s3.enabled) {
		prefix = "";
	}

	size_t ret = fbr_snprintf(buffer, buffer_len, "%s/%s", prefix, path);

	return ret;
}

size_t
fbr_cstore_s3_chunk_url(struct fbr_cstore *cstore, struct fbr_file *file, struct fbr_chunk *chunk,
    char *buffer, size_t buffer_len)
{
	fbr_cstore_ok(cstore);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(buffer);
	assert(buffer_len);

	char path[FBR_PATH_MAX];
	fbr_cstore_path_chunk(NULL, file, chunk->id, chunk->offset, 0, path, sizeof(path));

	size_t ret = fbr_cstore_s3_url(cstore, path, buffer, buffer_len);

	return ret;
}
