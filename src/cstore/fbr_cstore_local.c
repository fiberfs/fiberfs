/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore.h"
#include "fbr_cstore_api.h"
#include "core/fs/fbr_fs.h"

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

	unsigned long request_id = FBR_REQID_CSTORE;
	struct fbr_request *request = fbr_request_get();
	if (request) {
		request_id = request->id;
	}
	fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "writing wbuffer...");

	struct fbr_cstore_entry *entry = fbr_cstore_insert(cstore, hash, wbuffer->end);
	if (!entry) {
		return 1;
	}

	fbr_cstore_set_loading(entry);
	if (entry->state != FBR_CSTORE_LOADING) {
		fbr_cstore_release(cstore, entry);
		return 1;
	}

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);


	return 0;
}
