/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>

#include "fiberfs.h"
#include "fbr_fuse.h"
#include "core/context/fbr_callback.h"

extern void fbr_test_context_abort(void);

/*
 * The abort processs is meant to gracefully exit all Fiber threads/processes which will
 * then allow for a clean fuse unmount.
 *
 * When a single thread/process detects an error via assert()/abort() or gets a fault or
 * external signal to exit, it dumps a backtrace and then proceeds to a context abort.
 * (See fbr_assert.c and fbr_assert.h)
 *
 * The default context abort (fbr_context_abort() below) behaves as follows:
 *
 * 1. If the thread is a fuse request thread, then the following steps happen:
 *    a. The Fiber context is marked as error. This signals all Fiber threads/processes that
 *       a problem exists and they will abort themselves thru this function or
 *       exit in better way (if they care). See fbr_fuse_mounted() and fbr_request_valid().
 *    b. fuse_session_exit() is called. This tells fuse to exit at its next opportunity.
 *    c. If the fuse_req is un-replied, an EIO is sent back.
 *    d. pthread_exit() is called. This finishes the fuse request and allows for Fiber to
 *       continue to operate normally, albeit in a error state.
 *
 * 2. The thread/process is not a fuse request, the following happens:
 *    a. The Fiber context is marked as error. See 1a above.
 *    b. Fiber starts the internal unmount process:
 *       aa. fuse_session_exit() is called.
 *       bb. System umount is called on the mount (fusermount -u).
 *       cc. Wait for fuse_session_loop() to exit.
 *       dd. fuse_session_unmount() is called.
 *
 *       NOTE: all non-fuse threads/processes will block here until this step is completed.
 *
 * 3. If this is a fiber_test context, the test will abort and exit() with an error.
 *    (See fbr_test_context_abort() in fbr_test.c)
 *
 * 4. If not a fiber_test context, abort() is called. (See fbr_assert.c)
 */

void
fbr_context_abort(void)
{
	struct fbr_request *request = fbr_request_get();

	if (!request) {
		fbr_fuse_unmount_signal();
		fbr_test_context_abort();
		return;
	}

	if (request->fuse_ctx) {
		request->fuse_ctx->error = 1;
		fuse_session_exit(request->fuse_ctx->session);
	}

	if (request->fuse_req) {
		fuse_reply_err(request->fuse_req, EIO);
		request->fuse_req = NULL;
	}

	pthread_exit(NULL);
}
