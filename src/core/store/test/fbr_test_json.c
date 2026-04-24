/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <fcntl.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_callback.h"
#include "utils/fbr_sys.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

static void
_index_hash_ok(struct fbr_cstore *cstore, fbr_hash_t hash)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	fbr_cstore_entry_ok(entry);
	assert(entry->state == FBR_CSTORE_OK);
	fbr_cstore_release(cstore, &entry);
	assert_zero(entry);
}

static size_t
_index_print_file(const char *path)
{
	assert(path);

	int fd = open(path, O_RDONLY);
	assert(fd >= 0);

	char buffer[4096];
	size_t total = 0;
	ssize_t bytes;

	while ((bytes = fbr_sys_read(fd, buffer, sizeof(buffer) - 1)) > 0) {
		assert(bytes > 0 && (size_t)bytes < sizeof(buffer));
		buffer[bytes] = '\0';
		fbr_test_logs("%s", buffer);
		total += bytes;
	}

	assert_zero(bytes);

	assert_zero(close(fd));

	return total;
}

static void
_index_print_root(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	fbr_hash_t hash = fbr_cstore_hash_root(cstore, FBR_DIRNAME_ROOT);
	_index_hash_ok(cstore, hash);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);

	struct fbr_cstore_metadata metadata;
	fbr_cstore_metadata_read(&hashpath, &metadata);
	assert_zero(metadata.error);

	char id_str[FBR_ID_STRING_MAX];
	fbr_id_string(metadata.etag, id_str, sizeof(id_str));

	fbr_test_logs(" * ROOT");
	fbr_test_logs(" *** metadata.path: '%s'", metadata.path);
	fbr_test_logs(" *** metadata.etag: '%s' (%lu)", id_str, metadata.etag);
	fbr_test_logs(" *** metadata.size: %lu", metadata.size);

	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	assert_zero(metadata.gzipped);
	size_t size = _index_print_file(hashpath.value);
	assert(size == metadata.size);
}

void
fbr_cmd_index_print_json(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_test_fs_mock(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_bind_new(fs);
	fbr_cstore_ok(fs->cstore);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);

	fbr_test_fs_root_alloc(fs);

	fbr_test_cstore_debug(fs->cstore);

	assert(fs->cstore->entries == 2);

	_index_print_root(fs);

	fbr_fs_free(fs);

	fbr_test_logs("index_print_json done");
}
