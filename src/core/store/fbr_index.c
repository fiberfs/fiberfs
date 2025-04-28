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

	struct fbr_writer json;
	fbr_writer_init(fs, &json, 1);

	fbr_writer_add(fs, &json, "TODO", 4);
	fbr_writer_add(fs, &json, NULL, 0);

	fbr_writer_debug(fs, &json);

	fbr_writer_free(fs, &json);

	return 1;
}
