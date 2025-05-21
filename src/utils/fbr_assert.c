/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <errno.h>
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
static int _ASSERT_SPLIT_TRACE;

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
	void *stack_addrs[16];
	char **stack_syms = NULL;
	int addrs_len = backtrace(stack_addrs, fbr_array_len(stack_addrs));
	int syms_len = 0;
	int do_backtrace = 1;

	if (fbr_libunwind_enabled()) {
		if (errno != ENOMEM && !_ASSERT_SPLIT_TRACE) {
			stack_syms = backtrace_symbols(stack_addrs, addrs_len);
			syms_len = addrs_len;
			do_backtrace = 0;
		}

		fbr_libunwind_backtrace(stack_syms, syms_len);
	}

	if (do_backtrace) {
		fprintf(stderr, "\nBacktrace (addr2line -spfe [file] [+address]):\n");
		backtrace_symbols_fd(stack_addrs, addrs_len, STDERR_FILENO);
	}

	fprintf(stderr, "\n");
}

void __fbr_attr_printf(5) __fbr_noreturn
fbr_do_abort(const char *assertion, const char *function, const char *file, int line,
    const char *fmt, ...)
{
	unsigned long count = fbr_atomic_add(&_ASSERT_LOOP, 1);

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
