/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FIBERFS_H_INCLUDED_
#define _FIBERFS_H_INCLUDED_

#define FIBERFS_VERSION				"0.8.0"

typedef unsigned int fbr_refcount_t;
typedef unsigned int fbr_bitflag_t;
typedef unsigned long fbr_inode_t;
typedef unsigned long fbr_stats_t;

#include "utils/fbr_assert.h"
#include "utils/fbr_id.h"
#include "utils/fbr_utils.h"

typedef void __fbr_attr_printf(1) (fbr_log_f)(const char *fmt, ...);

#define fbr_magic_check(obj, value)				\
{								\
	assert(obj);						\
	assert((obj)->magic == (value));			\
}
#define fbr_magic_check_dev(obj, value)				\
{								\
	assert_dev(obj);					\
	assert_dev((obj)->magic == (value));			\
}
#define fbr_zero_magic(obj)					\
{								\
	(obj)->magic = 0;					\
}
#define fbr_object_empty(obj)					\
	fbr_magic_check(obj, 0)
#define fbr_object_is_empty(obj)				\
	((obj) && !((obj)->magic))

#endif /* _FIBERFS_H_INCLUDED_ */
