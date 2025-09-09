/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "fbr_cstore_io.h"
#include "core/fs/fbr_fs.h"
#include "utils/fbr_xxhash.h"

static void
_chash_fs(XXH3_state_t *hash, struct fbr_fs *fs)
{
	assert_dev(hash);
	assert_dev(fs);

	// TODO
}

static void
_chash_file_path(XXH3_state_t *hash, struct fbr_file *file, fbr_id_t id, size_t offset)
{
	assert_dev(hash);
	assert_dev(file);
	assert_dev(id);

	char buffer[FBR_PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, buffer, sizeof(buffer));

	XXH3_64bits_update(hash, filepath.name, filepath.len);

	buffer[0] = '.';
	size_t buffer_len = 1;

	buffer_len += fbr_id_string(id, buffer + buffer_len, sizeof(buffer) - buffer_len);
	int ret = snprintf(buffer + buffer_len, sizeof(buffer) - buffer_len, ".%zu", offset);
	assert(ret > 0 && (size_t)ret < (sizeof(buffer) - buffer_len));

	buffer_len += ret;
	assert(buffer_len < sizeof(buffer));

	XXH3_64bits_update(hash, buffer, buffer_len + 1);
}

/*
static void
_chash_external(XXH3_state_t *hash, fbr_id_t id)
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
_chash_range(XXH3_state_t *hash, size_t offset, size_t length)
{
	assert_dev(hash);
	assert_dev(length);

	(void)offset;

	fbr_ABORT("TODO");
}
*/

fbr_hash_t
fbr_chash_chunk(struct fbr_fs *fs, struct fbr_file *file, fbr_id_t id, size_t offset)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(id);

	XXH3_state_t hash;
	XXH3_INITSTATE(&hash);
	XXH3_64bits_reset(&hash);

	_chash_fs(&hash, fs);
	_chash_file_path(&hash, file, id, offset);

	XXH64_hash_t result = XXH3_64bits_digest(&hash);
	static_ASSERT(sizeof(result) == sizeof(fbr_hash_t));

	return (fbr_hash_t)result;
}

static void
_chash_directory_path(XXH3_state_t *hash, struct fbr_directory *directory)
{
	assert_dev(hash);
	assert_dev(directory);

	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);

	XXH3_64bits_update(hash, dirpath.name, dirpath.len);

	if (dirpath.len) {
		XXH3_64bits_update(hash, "/", 1);
	}
	XXH3_64bits_update(hash, ".fiberfsindex.", 14);

	char id_buffer[FBR_ID_STRING_MAX];
	size_t id_len = fbr_id_string(directory->version, id_buffer, sizeof(id_buffer));

	XXH3_64bits_update(hash, id_buffer, id_len + 1);
}

fbr_hash_t
fbr_chash_index(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	XXH3_state_t hash;
	XXH3_INITSTATE(&hash);
	XXH3_64bits_reset(&hash);

	_chash_fs(&hash, fs);
	_chash_directory_path(&hash, directory);

	XXH64_hash_t result = XXH3_64bits_digest(&hash);
	static_ASSERT(sizeof(result) == sizeof(fbr_hash_t));

	return (fbr_hash_t)result;
}
