/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "fbr_fs.h"

void
fbr_fs_stat_add_count(unsigned long *stat, unsigned long value)
{
	assert(stat);

	(void)__sync_add_and_fetch(stat, value);
}

void
fbr_fs_stat_add(unsigned long *stat)
{
	fbr_fs_stat_add_count(stat, 1);
}

void
fbr_fs_stat_sub_count(unsigned long *stat, unsigned long value)
{
	assert(stat);

	(void)__sync_sub_and_fetch(stat, value);
}

void
fbr_fs_stat_sub(unsigned long *stat)
{
	fbr_fs_stat_sub_count(stat, 1);
}

double
fbr_fs_dentry_ttl(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	if (fs->config.dentry_ttl <= 0) {
		return (double)FBR_TTL_MAX;
	}

	return fs->config.dentry_ttl;
}

void __fbr_attr_printf(1)
fbr_fs_logger(const char *fmt, ...)
{
	char vbuf[4096];

	va_list ap;
	va_start(ap, fmt);

	(void)vsnprintf(vbuf, sizeof(vbuf), fmt, ap);

	va_end(ap);

	printf("%s\n", vbuf);
}

size_t
fbr_fs_block_size(size_t offset)
{
	/*
	 * offset range     block size
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
