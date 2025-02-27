/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"

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
