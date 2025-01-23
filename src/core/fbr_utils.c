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

void __fbr_attr_printf_p(6)
fbr_do_assert(int cond, const char *function, const char *file, int line, int assert,
    const char *fmt, ...)
{
	va_list ap;

	if (cond) {
		return;
	}

	fprintf(stderr, "%s:%d %s(): %s\n", file, line, function,
		assert ? "Assertion failed" : "Aborted");

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	printf("\n");

	abort();
}

void
fbr_sleep_ms(long ms)
{
	struct timespec tspec, rem;

	assert(ms >= 0);

	tspec.tv_sec = ms / 1000;
	tspec.tv_nsec = (ms % 1000) * 1000 * 1000;

	errno = 0;
	while (nanosleep(&tspec, &rem) && errno == EINTR) {
		tspec.tv_sec = rem.tv_sec;
		tspec.tv_nsec = rem.tv_nsec;
		errno = 0;
	}
}
