/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_lowlevel.h"

#include <pthread.h>
#include <stdio.h>

void __fbr_attr_printf_p(7)
fbr_fuse_do_assert(int cond, void *req, const char *assertion, const char *function,
    const char *file, int line, const char *fmt, ...)
{
	if (cond) {
		return;
	}

	fprintf(stderr, "%s:%d %s(): Assertion '%s' failed\n", file, line, function, assertion);

	if (fmt) {
		fprintf(stderr, "ERROR: ");

		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	} else {
		fprintf(stderr, "ERROR");
	}

	fprintf(stderr, "\n");

	// TODO make this non recursive assert wise
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx();

	ctx->error = 1;

	fbr_fuse_abort(ctx);

	if (req) {
		fuse_req_t freq = (fuse_req_t) req;
		(void)fuse_reply_err(freq, EIO);
	}

	pthread_exit(NULL);
}
