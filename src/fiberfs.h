/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FIBERFS_H_INCLUDED_
#define _FIBERFS_H_INCLUDED_

#include <string.h>

#include "utils/fbr_utils.h"

#define FIBERFS_VERSION			"0.1.0"

#define fbr_ZERO(p)								\
	explicit_bzero(p, sizeof(*(p)))

#endif /* _FIBERFS_H_INCLUDED_ */
