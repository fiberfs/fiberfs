/*
 * Copyright (c) 2024 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_UTILS_H_INCLUDED_
#define _FBR_UTILS_H_INCLUDED_

#include <string.h>

void fbr_sleep_ms(long ms);
double fbr_get_time(void);

#define fbr_atomic_add(dest_ptr, value)			\
	__sync_add_and_fetch(dest_ptr, value);
#define fbr_atomic_sub(dest_ptr, value)			\
	__sync_sub_and_fetch(dest_ptr, value);

#define fbr_ZERO(p)					\
	explicit_bzero(p, sizeof(*(p)))

#define fbr_array_len(array)				\
	(sizeof(array) / sizeof(*(array)))

#endif /* _FBR_UTILS_H_INCLUDED_ */
