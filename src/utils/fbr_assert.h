/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_ASSERT_H_INCLUDED_
#define _FBR_ASSERT_H_INCLUDED_

#ifndef _ASSERT_H
#define	_ASSERT_H
#endif

#define __fbr_attr_printf(fpos)							\
	__attribute__((__format__(__printf__, (fpos), ((fpos) + 1))))
#define __fbr_noreturn								\
	__attribute__ ((__noreturn__))

void fbr_setup_crash_signals(void);
int fbr_assert_is_dev(void);
void __fbr_attr_printf(5) __fbr_noreturn fbr_do_abort(const char *assertion,
	const char *function, const char *file, int line, const char *fmt, ...);
int fbr_libunwind_enabled(void);
void fbr_libunwind_backtrace(void);

#undef assert
#undef assert_zero

#define assert(expr)								\
	fbr_ASSERT(expr, NULL)
#define assert_zero(expr)							\
	fbr_ASSERT(!(expr), NULL)
#define pt_assert(expr)								\
	fbr_ASSERT(!(expr), NULL)
#define fbr_void(expr)								\
	(void)(expr)
#define fbr_ABORT(fmt, ...)							\
	fbr_do_abort(NULL, __func__, __FILE__, __LINE__, fmt, ##__VA_ARGS__);
#define fbr_ASSERT(cond, fmt, ...)						\
{										\
	if (__builtin_expect(!(cond), 0)) {					\
		fbr_do_abort(#cond, __func__, __FILE__, __LINE__, fmt,		\
			##__VA_ARGS__);						\
	}									\
}

#ifdef FBR_NO_ASSERT_DEV
#define assert_dev(expr)							\
	fbr_void(expr)
#define assert_zero_dev(expr)							\
	fbr_void(expr)
#else
#define assert_dev(expr)							\
	assert(expr)
#define assert_zero_dev(expr)							\
	assert_zero(expr)
#endif

#endif /* _FBR_ASSERT_H_INCLUDED_ */
