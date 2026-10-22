/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_CHECK_H_INCLUDED_
#define _FBR_CHECK_H_INCLUDED_

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
#define fbr_object_is_valid(obj, value)				\
	((obj) && (obj)->magic == (value))

#endif /* _FBR_CHECK_H_INCLUDED_ */
