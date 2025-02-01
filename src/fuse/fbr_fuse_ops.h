/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_FUSE_OPS_H_INCLUDED_
#define _FBR_FUSE_OPS_H_INCLUDED_

#include "fiberfs.h"
#include "fbr_fuse_lowlevel.h"

struct fbr_fuse_context *fbr_fuse_get_ctx(fuse_req_t req);
void __fbr_attr_printf_p(6) fbr_fuse_do_assert(fuse_req_t req, const char *assertion,
	const char *function, const char *file, int line, const char *fmt, ...);

#define fbr_fuse_ASSERT(cond, req)						\
{										\
	if (cond) {								\
		;								\
	} else {								\
		fbr_fuse_do_assert(req, #cond, __func__, __FILE__, __LINE__,	\
			NULL);							\
	}									\
}
#define fbr_fuse_ASSERTF(cond, req, fmt, ...)					\
{										\
	if (cond) {								\
		;								\
	} else {								\
		fbr_fuse_do_assert(cond, req, #cond, __func__, __FILE__, 	\
			__LINE__, fmt, ##__VA_ARGS__);				\
	}									\
}

#endif /* _FBR_FUSE_OPS_H_INCLUDED_ */
