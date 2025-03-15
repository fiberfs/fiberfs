/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <execinfo.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fbr_assert.h"
#include "fbr_utils.h"

extern void fbr_context_abort(void);

static unsigned long _ASSERT_LOOP;

void
fbr_signal_catcher(int signal, siginfo_t *info, void *ucontext)
{
	(void)info;
	(void)ucontext;

	fbr_ABORT("Caught signal: %s (%d)", strsignal(signal), signal);
}


void
fbr_setup_crash_signals(void)
{
	struct sigaction sa;
	fbr_ZERO(&sa);
	sa.sa_sigaction = fbr_signal_catcher;
	sa.sa_flags = SA_SIGINFO;

	assert_zero(sigaction(SIGSEGV, &sa, NULL));
	assert_zero(sigaction(SIGTERM, &sa, NULL));
	assert_zero(sigaction(SIGINT, &sa, NULL));
	assert_zero(sigaction(SIGBUS, &sa, NULL));
	assert_zero(sigaction(SIGILL, &sa, NULL));
	assert_zero(sigaction(SIGPIPE, &sa, NULL));
}

int
fbr_assert_is_dev(void)
{
#ifdef FBR_NO_ASSERT_DEV
	return 0;
#else
	return 1;
#endif
}

static void
_dump_backtrace(void)
{
	if (fbr_libunwind_enabled()) {
		fbr_libunwind_backtrace();
	}

	fprintf(stderr, "\nBacktrace (addr2line -spfe [file] [+address]):\n");

	void *stack_addrs[16];
	int len = backtrace(stack_addrs, fbr_array_len(stack_addrs));
	backtrace_symbols_fd(stack_addrs, len, STDERR_FILENO);
}

/*
 * The abort processs is meant to allow for a clean exit of all Fiber threads/processes
 * which will allow for a clean fuse unmount.
 *
 * When a single thread/process detects an error via assert()/abort() or gets a fault or
 * external signal to exit, it dumps a backtrace and then proceeds to a context abort.
 *
 * The default fbr_context_abort() (see fbr_fuse_abort.c) behaves as follows:
 *
 * 1. If the thread is a fuse request thread, then the following steps happen:
 *    a. The Fiber context is marked as error. This signals all Fiber threads/processes that
 *       a problem exists and they will abort themselves thru this function or
 *       exit in better way (if they care). See fbr_fuse_mounted() and fbr_request_ok().
 *    b. fuse_session_exit() is called. This tells fuse to exit at its next opportunity.
 *    c. If the fuse_req is un-replied, reply to it with an EIO.
 *    d. pthread_exit() is called. This finishes the fuse request and allows for Fiber to
 *       continue to operate normally, albeit in a error state.
 *
 * 2. The thread/process is not a fuse request, the following happens:
 *    a. The Fiber context is marked as error. See 1.a. above.
 *    b. Fiber starts the internal unmount process:
 *       aa. fuse_session_exit() is called.
 *       bb. System umount is called on the mount (fusermount -u).
 *       cc. Wait for fuse_session_loop() to exit.
 *       dd. fuse_session_unmount() is called.
 *
 *       NOTE: all non-fuse threads/processes will block here until this step is completed.
 *
 * 3. If this is a fiber_test context, the test will exit() with an error.
 *
 * 4. If not a fiber_test context, abort() is called.
 */

void __fbr_attr_printf(5) __fbr_noreturn
fbr_do_abort(const char *assertion, const char *function, const char *file, int line,
    const char *fmt, ...)
{
	unsigned long count = fbr_safe_add(&_ASSERT_LOOP, 1);

	fprintf(stderr, "%s:%d %s(): ", file, line, function);

	if (assertion) {
		fprintf(stderr, "Assertion '%s' failed\n", assertion);
	} else {
		fprintf(stderr, "Aborted\n");
	}

	if (fmt) {
		va_list ap;
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fprintf(stderr, "\n");
	}

	if (count <= 3) {
		_dump_backtrace();

		if (count == 1) {
			// TODO get more details on this context like thread name, etc
		}
	} else if (count > 32) {
		fprintf(stderr, "ERROR: too many aborts (%lu), exiting\n", count);
		abort();
	}

	fbr_context_abort();

	abort();
}
