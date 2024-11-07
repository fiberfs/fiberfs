/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FIBERFS_H_INCLUDED_
#define _FIBERFS_H_INCLUDED_

#include <assert.h>
#include <string.h>

#define FIBERFS_VERSION			"0.1.0"

#define __fbr_attr_printf						\
	__fbr_attr_printf_p(2)
#define __fbr_attr_printf_p(fpos)					\
	__attribute__((__format__(__printf__, (fpos), ((fpos) + 1))))

#define assert_zero(expr)						\
	assert(!(expr))
#define fbr_ZERO(p)							\
	explicit_bzero(p, sizeof(*(p)))

#endif /* _FIBERFS_H_INCLUDED_ */
