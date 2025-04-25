/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_store.h"

int
fbr_store_index(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_json_writer json;
	fbr_json_writer_init(fs, &json);

	fbr_json_writer_debug(fs, &json);

	fbr_json_writer_free(fs, &json);

	return 1;
}
