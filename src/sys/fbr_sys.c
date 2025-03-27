/*
 * Copyright (c) 2024 FiberFS
 *
 */

#define _XOPEN_SOURCE 500

#include <ftw.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_sys.h"

static mode_t
_sys_mode(const char *path)
{
	struct stat st;

	int ret = lstat(path, &st);

	if (ret) {
		return 0;
	}

	return st.st_mode;
}

int
fbr_sys_exists(const char *path)
{
	mode_t st_mode = _sys_mode(path);

	if (st_mode) {
		return 1;
	}

	return 0;
}

int
fbr_sys_isdir(const char *path)
{
	mode_t st_mode = _sys_mode(path);

	if (S_ISDIR(st_mode)) {
		return 1;
	}

	return 0;
}

static int
_sys_rmdir_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
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
fbr_sys_rmdir(const char *path)
{
	(void)nftw(path, _sys_rmdir_cb, 64, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
}

size_t
fbr_sys_write(int fd, const void *buf, size_t buf_len)
{
	assert(fd >= 0);
	assert(buf);
	assert(buf_len);

	size_t bytes = 0;

	while (bytes < buf_len) {
		ssize_t ret = write(fd, (const char*)buf + bytes, buf_len - bytes);
		if (ret <= 0) {
			return 0;
		}

		bytes += ret;
	}

	assert_dev(bytes == buf_len);

	return bytes;
}

ssize_t
fbr_sys_read(int fd, void *buf, size_t buf_len)
{
	assert(fd >= 0);
	assert(buf);
	assert(buf_len);

	size_t bytes = 0;
	ssize_t ret;

	do {
		ret = read(fd, (char*)buf + bytes, buf_len - bytes);
		if (ret < 0) {
			return ret;
		}

		bytes += ret;
	} while (ret && bytes < buf_len);

	return bytes;
}
