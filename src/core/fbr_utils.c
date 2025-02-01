/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "fiberfs.h"

void __fbr_attr_printf_p(5)
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

	abort();
}

void
fbr_sleep_ms(long ms)
{
	assert(ms >= 0);

	struct timespec tspec, rem;

	tspec.tv_sec = ms / 1000;
	tspec.tv_nsec = (ms % 1000) * 1000 * 1000;

	errno = 0;
	while (nanosleep(&tspec, &rem) && errno == EINTR) {
		tspec.tv_sec = rem.tv_sec;
		tspec.tv_nsec = rem.tv_nsec;
		errno = 0;
	}
}
