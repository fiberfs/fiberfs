/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_ASSERT_H_INCLUDED_
#define _FBR_ASSERT_H_INCLUDED_

#define	_ASSERT_H

#define __fbr_attr_printf(fpos)							\
	__attribute__((__format__(__printf__, (fpos), ((fpos) + 1))))

void __fbr_attr_printf(5) fbr_do_abort(const char *assertion, const char *function,
	const char *file, int line, const char *fmt, ...);

#undef assert
#define assert(expr)								\
	fbr_ASSERT(expr, NULL)
#define assert_zero(expr)							\
	fbr_ASSERT(!(expr), NULL)
#define fbr_ABORT(fmt, ...)							\
	fbr_do_abort(NULL, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__);
#define fbr_ASSERT(cond, fmt, ...)						\
{										\
	if (__builtin_expect(!(cond), 0)) {					\
		fbr_do_abort(#cond, __func__, __FILE__, __LINE__, fmt,		\
			##__VA_ARGS__);						\
	}									\
}

#endif /* _FBR_ASSERT_H_INCLUDED_ */
