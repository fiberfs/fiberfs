/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fbr_fuse.h"
#include "fbr_fuse_lowlevel.h"
#include "fbr_fuse_ops.h"

#include <pthread.h>
#include <stdio.h>

struct fbr_fuse_context *_FUSE_CTX;

struct fbr_fuse_context *
fbr_fuse_get_ctx(fuse_req_t req)
{
	fbr_fuse_ASSERT(_FUSE_CTX != NULL, req);
	fbr_fuse_ASSERT(_FUSE_CTX->magic == FBR_FUSE_CTX_MAGIC, req);
	fbr_fuse_ASSERT(_FUSE_CTX->exited == 0, req);

	return _FUSE_CTX;
}

void __fbr_attr_printf(6)
fbr_fuse_do_assert(fuse_req_t req, const char *assertion, const char *function,
    const char *file, int line, const char *fmt, ...)
{
	fprintf(stderr, "%s:%d %s(): Assertion '%s' failed\n", file, line, function, assertion);

	if (fmt) {
		fprintf(stderr, "ERROR: ");

		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);

		fprintf(stderr, "\n");
	} else {
		fprintf(stderr, "ERROR\n");
	}

	fbr_fuse_ctx_ok(_FUSE_CTX);

	_FUSE_CTX->error = 1;

	fbr_fuse_abort(_FUSE_CTX);

	if (req) {
		(void)fuse_reply_err(req, EIO);
	}

	pthread_exit(NULL);
}
