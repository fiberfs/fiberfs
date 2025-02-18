/*
 * Copyright (c) 2024 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_UTILS_H_INCLUDED_
#define _FBR_UTILS_H_INCLUDED_

#include <string.h>

void fbr_sleep_ms(long ms);

#define fbr_ZERO(p)				\
	explicit_bzero(p, sizeof(*(p)))

#endif /* _FBR_UTILS_H_INCLUDED_ */
