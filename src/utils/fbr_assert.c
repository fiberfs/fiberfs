/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "fiberfs.h"

void __fbr_attr_printf(5) __fbr_noreturn
fbr_do_abort(const char *assertion, const char *function, const char *file, int line,
    const char *fmt, ...)
{
	// TODO do stack trace

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

	// TODO get fiber context

	abort();
}
