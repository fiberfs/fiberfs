/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>

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

int
fbr_fs_timeout_expired(double time_start, double timeout)
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

size_t
fbr_fs_chunk_size(size_t offset)
{
	/*
	 * offset range     chunk size
	 *   0KB - 256KB  :   64KB
	 * 256KB -   1MB  :  256KB
	 *   1MB -   4MB  :  512KB
	 *   4MB -  10MB  :    1MB
	 *  10MB -     *  :    2MB
	 */

	if (offset <= 1024 * 256) {
		return 1024 * 64;
	} else if (offset <= 1024 * 1024) {
		return 1024 * 256;
	} else if (offset <= 1024 * 1024 * 4) {
		return 1024 * 512;
	} else if (offset <= 1024 * 1024 * 10) {
		return 1024 * 1024;
	}

	return 1024 * 1024 * 2;
}
