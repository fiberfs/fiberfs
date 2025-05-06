/*
 * Copyright (c) 2024 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_UTILS_H_INCLUDED_
#define _FBR_UTILS_H_INCLUDED_

#include <string.h>
#include <time.h>

void fbr_sleep_ms(double ms);
double fbr_get_time(void);
void fbr_timespec_add_clock(struct timespec *value);
unsigned long fbr_parse_ulong(const char *str, size_t length);

#define _FBR_STRINGIFY(_value)			#_value
#define FBR_STRINGIFY(value)			_FBR_STRINGIFY(value)

#define fbr_atomic_add(dest_ptr, value)					\
	__sync_add_and_fetch(dest_ptr, value);
#define fbr_atomic_sub(dest_ptr, value)					\
	__sync_sub_and_fetch(dest_ptr, value);
#define fbr_compare_swap(dest_ptr, old_value, new_value)		\
	__sync_val_compare_and_swap(dest_ptr, old_value, new_value)

#define fbr_ZERO(p)							\
	explicit_bzero(p, sizeof(*(p)))

#define fbr_array_len(array)						\
	(sizeof(array) / sizeof(*(array)))

#endif /* _FBR_UTILS_H_INCLUDED_ */
