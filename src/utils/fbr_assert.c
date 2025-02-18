/*
 * Copyright (c) 2024 FiberFS
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

static void
_dump_backtrace(void)
{
	if (fbr_libunwind_enabled()) {
		fbr_libunwind_backtrace();
	}

	fprintf(stderr, "\nBacktrace (addr2line -e [file] [+address]):\n");

	void *stack_addrs[16];
	int len = backtrace(stack_addrs, sizeof(stack_addrs) / sizeof(*stack_addrs));
	backtrace_symbols_fd(stack_addrs, len, STDERR_FILENO);
}

void __fbr_attr_printf(5) __fbr_noreturn
fbr_do_abort(const char *assertion, const char *function, const char *file, int line,
    const char *fmt, ...)
{
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

	_dump_backtrace();

	fbr_context_abort();

	abort();
}
