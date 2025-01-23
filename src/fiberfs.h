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

void __fbr_attr_printf_p(6) fbr_do_assert(int cond, const char *function, const char *file,
	int line, int assert, const char *fmt, ...);
void fbr_sleep_ms(long ms);

#define assert_zero(expr)						\
	assert(!(expr))
#define fbr_ZERO(p)							\
	explicit_bzero(p, sizeof(*(p)))
#define fbr_ABORT(fmt, ...)						\
	fbr_do_assert(1, __func__, __FILE__, __LINE__, 0, fmt,		\
		##__VA_ARGS__);
#define fbr_ASSERT(cond, fmt, ...)					\
	fbr_do_assert(cond, __func__, __FILE__, __LINE__, 1, fmt,	\
		##__VA_ARGS__);

#endif /* _FIBERFS_H_INCLUDED_ */
