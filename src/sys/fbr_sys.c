/*
 * Copyright (c) 2024 FiberFS
 *
 */

#define _XOPEN_SOURCE 500

#include <errno.h>
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
_sys_rmdir_cb(const char *filename, const struct stat *stat, int flag, struct FTW *info)
{
	(void)stat;
	(void)info;

	switch (flag) {
		case FTW_F:
		case FTW_SL:
			(void)unlink(filename);
			break;
		case FTW_DP:
			(void)rmdir(filename);
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

int
fbr_sys_nftw(const char *path, fbr_nftw_func_t func)
{
	return nftw(path, func, 64, FTW_DEPTH | FTW_MOUNT | FTW_PHYS);
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

int
fbr_mkdirs(const char *path)
{
	assert(path);

	size_t path_len = strlen(path);
	assert(path_len < FBR_PATH_MAX);

	char path_buf[FBR_PATH_MAX];
	memcpy(path_buf, path, path_len + 1);

	for (size_t i = 1; i < path_len; i++) {
		if (path_buf[i] == '/') {
			path_buf[i] = '\0';

			int ret = mkdir(path_buf, S_IRWXU);
			if (ret && errno != EEXIST) {
				return ret;
			}

			path_buf[i] = '/';
		}
	}

	return 0;
}
