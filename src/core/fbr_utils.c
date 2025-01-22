/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

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
