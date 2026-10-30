/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <sys/stat.h>

#include "fiberfs.h"
#include "fbr_fs.h"

double
fbr_fs_dentry_ttl(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	if (fs->config.dentry_ttl <= 0) {
		return (double)FBR_TTL_MAX;
	}

	return fs->config.dentry_ttl;
}

unsigned long
fbr_fs_param_value(unsigned long param)
{
	if (param == 0) {
		return INT32_MAX;
	}

	return param;
}

size_t
fbr_fs_chunk_size(size_t offset)
{
	/*
	 * offset range     chunk size
	 *   0KB - 256KB  :   64KB
	 * 256KB -   1MB  :  256KB
	 *   1MB -   8MB  :  512KB
	 *   8MB -  20MB  :    1MB
	 *  20MB -     *  :    2MB
	 */

	if (offset < 1024 * 256) {
		return 1024 * 64;
	} else if (offset < 1024 * 1024) {
		return 1024 * 256;
	} else if (offset < 1024 * 1024 * 8) {
		return 1024 * 512;
	} else if (offset < 1024 * 1024 * 20) {
		return 1024 * 1024;
	}

	return 1024 * 1024 * 2;
}

void
fbr_fs_timeout_init(struct fbr_fs_timeout *timeout)
{
	assert(timeout);

	timeout->attempts = 0;
	timeout->time_start = fbr_get_time();
}

static int
_timeout_expired(double time_start, double timeout)
{
	if (timeout <= 0) {
		return 0;
	}

	double time_now = fbr_get_time();
	if (time_now - time_start > timeout) {
		return 1;
	}

	return 0;
}

int
fbr_fs_is_timeout(struct fbr_fs *fs, struct fbr_fs_timeout *timeout)
{
	fbr_fs_ok(fs);
	assert(timeout);

	timeout->attempts++;

	if (timeout->attempts >= fbr_fs_param_value(fs->config.flush_attempts)) {
		fbr_rlog(FBR_LOG_ERROR, "timeout attempt limit hit on write %u", timeout->attempts);
		return 1;
	} else if (_timeout_expired(timeout->time_start, fs->config.flush_timeout_sec)) {
		fbr_rlog(FBR_LOG_ERROR, "timeout time limit hit on write %lf",
			fbr_get_time() - timeout->time_start);
		return 1;
	}

	return 0;
}

int
fbr_fs_check_access(uid_t uid, gid_t gid, const struct fbr_file *file, int access)
{
	fbr_file_ok(file);

	int file_mask = R_OK | W_OK | X_OK;
	assert(fbr_is_flag(access, file_mask));

	if (!uid) {
		return 1;
	}

	mode_t perm = 0;

	if (uid == file->uid) {
		perm = (file->mode >> 6) & file_mask;
	} else if (gid == file->gid) {
		perm = (file->mode >> 3) & file_mask;
	} else {
		perm = file->mode & file_mask;
	}

	if ((access & R_OK) && !(perm & R_OK)) {
		return 0;
	}
	if ((access & W_OK) && !(perm & W_OK)) {
		return 0;
	}
	if ((access & X_OK) && !(perm & X_OK)) {
		return 0;
	}

	return 1;
}
