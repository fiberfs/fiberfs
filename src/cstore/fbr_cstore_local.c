/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "fbr_cstore.h"
#include "fbr_cstore_api.h"
#include "core/fs/fbr_fs.h"
#include "utils/fbr_sys.h"

void
_cstore_gen_path(struct fbr_cstore *cstore, fbr_hash_t hash, int metadata, char *output,
    size_t output_len)
{
	assert_dev(cstore);
	assert_dev(output);
	assert_dev(output_len);

	char hash_str[FBR_HASH_SLEN];
	fbr_bin2hex(&hash, sizeof(hash), hash_str, sizeof(hash_str));
	assert_dev(strlen(hash_str) > 4);

	const char *subpath = FBR_CSTORE_DATA_DIR;
	if (metadata) {
		subpath = FBR_CSTORE_META_DIR;
	}

	int ret = snprintf(output, output_len, "%s/%s/%.2s/%.2s/%s",
		cstore->root,
		subpath,
		hash_str,
		hash_str + 2,
		hash_str + 4);
	assert(ret > 0 && (size_t)ret < output_len);
}

int
fbr_cstore_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_READY);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 1;
	}

	fbr_hash_t hash = fbr_chash_wbuffer(fs, file, wbuffer);

	char buffer[FBR_PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, buffer, sizeof(buffer));

	unsigned long request_id = FBR_REQID_CSTORE;
	struct fbr_request *request = fbr_request_get();
	if (request) {
		request_id = request->id;
	}

	char path[FBR_PATH_MAX];
	_cstore_gen_path(cstore, hash, 0, path, sizeof(path));

	fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "%s %zu:%zu %lu %s",
		filepath.name, wbuffer->offset, wbuffer->end, wbuffer->id, path);

	struct fbr_cstore_entry *entry = fbr_cstore_insert(cstore, hash, wbuffer->end);
	if (!entry) {
		return 1;
	}

	fbr_cstore_set_loading(entry);
	if (entry->state != FBR_CSTORE_LOADING) {
		fbr_cstore_release(cstore, entry);
		return 1;
	}

	int ret = fbr_mkdirs(path);
	if (ret) {
		fbr_cstore_release(cstore, entry);
		return 1;
	}

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);


	return 0;
}
