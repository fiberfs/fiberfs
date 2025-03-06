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
	va_list ap;
	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	va_end(ap);
}
