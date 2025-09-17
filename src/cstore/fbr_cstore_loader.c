/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_cstore_api.h"

void
fbr_cstore_loader_init(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);
}

size_t
fbr_cstore_exists(struct fbr_cstore *cstore, fbr_hash_t hash)
{
	fbr_cstore_ok(cstore);

	if (cstore->loader.loaded) {
		return 0;
	}

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	struct stat st;
	int ret = lstat(path, &st);
	if (ret) {
		return 0;
	}

	if (!S_ISREG(st.st_mode)) {
		return 0;
	}

	return st.st_size;
}

void
fbr_cstore_loader_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);
}
