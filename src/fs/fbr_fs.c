/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fs/fbr_fs.h"

mode_t
_fs_mode(const char *path)
{
	struct stat st;
	int ret;

	ret = lstat(path, &st);

	if (ret) {
		return 0;
	}

	return st.st_mode;
}

int
fbr_fs_exists(const char *path)
{
	mode_t st_mode;

	st_mode = _fs_mode(path);

	if (st_mode) {
		return 1;
	}

	return 0;
}

int
fbr_fs_isdir(const char *path)
{
	mode_t st_mode;

	st_mode = _fs_mode(path);

	if (S_ISDIR(st_mode)) {
		return 1;
	}

	return 0;
}
