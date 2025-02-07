/*
 * Copyright (c) 2024 FiberFS
 *
 */

#define _XOPEN_SOURCE 500

#include <ftw.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fbr_sys.h"

static mode_t
_fs_mode(const char *path)
{
	struct stat st;

	int ret = lstat(path, &st);

	if (ret) {
		return 0;
	}

	return st.st_mode;
}

int
fbr_fs_exists(const char *path)
{
	mode_t st_mode = _fs_mode(path);

	if (st_mode) {
		return 1;
	}

	return 0;
}

int
fbr_fs_isdir(const char *path)
{
	mode_t st_mode = _fs_mode(path);

	if (S_ISDIR(st_mode)) {
		return 1;
	}

	return 0;
}

static int
_fs_rmdir_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	(void)sb;
	(void)ftwbuf;

	switch (typeflag) {
		case FTW_F:
		case FTW_SL:
			(void)unlink(fpath);
			break;
		case FTW_DP:
			(void)rmdir(fpath);
			break;
		default:
			break;
	}

	return 0;
}

void
fbr_rmdir(const char *path)
{
	(void)nftw(path, _fs_rmdir_cb, 64, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
}
