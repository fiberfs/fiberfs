/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_store.h"
#include "core/request/fbr_request.h"

int
fbr_store_index(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_request *request = fbr_request_get();
	fbr_request_ok(request);

	struct fbr_json_writer json;
	fbr_json_writer_init(&json);

	char *buffer = fbr_workspace_alloc(request->workspace, FBR_JSON_DEFAULT_BUFLEN);
	size_t buffer_len = FBR_JSON_DEFAULT_BUFLEN;

	if (!buffer) {
		return 0;
	}

	fbr_json_writer_add(fs, &json, buffer, buffer_len, 1);

	buffer = fbr_workspace_rbuffer(request->workspace);
	buffer_len = fbr_workspace_rlen(request->workspace);

	if (!buffer) {
		return 0;
	}

	if (buffer_len >= FBR_JSON_DEFAULT_BUFLEN * 2) {
		buffer_len -= FBR_JSON_DEFAULT_BUFLEN;
	} else if (buffer_len > FBR_JSON_DEFAULT_BUFLEN) {
		buffer_len = FBR_JSON_DEFAULT_BUFLEN;
	}

	fbr_workspace_ralloc(request->workspace, buffer_len);

	fbr_json_writer_add(fs, &json, buffer, buffer_len, 0);

	fbr_json_writer_debug(fs, &json);

	fbr_json_writer_free(&json);

	return 1;
}
