/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FIBERFS_H_INCLUDED_
#define _FIBERFS_H_INCLUDED_

#include "utils/fbr_assert.h"
#include "utils/fbr_id.h"
#include "utils/fbr_utils.h"

#define FIBERFS_VERSION				"0.1.0"

typedef unsigned int fbr_refcount_t;
typedef unsigned long fbr_inode_t;
typedef unsigned long fbr_stats_t;

typedef void __fbr_attr_printf(1) (fbr_log_f)(const char *fmt, ...);

#define fbr_magic_check(obj, value)				\
{								\
	assert(obj);						\
	assert((obj)->magic == value);				\
}

#endif /* _FIBERFS_H_INCLUDED_ */
