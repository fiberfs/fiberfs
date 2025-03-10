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
unsigned long fbr_safe_add(unsigned long *dest, unsigned long value);
unsigned long fbr_safe_sub(unsigned long *dest, unsigned long value);

#define fbr_ZERO(p)				\
	explicit_bzero(p, sizeof(*(p)))

#define fbr_array_len(array)			\
	(sizeof(array) / sizeof(*array))

#endif /* _FBR_UTILS_H_INCLUDED_ */
