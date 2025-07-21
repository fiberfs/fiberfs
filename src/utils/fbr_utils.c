/*
 * Copyright (c) 2024 FiberFS
 * All rights reserved.
 *
 */

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <time.h>

#include "fiberfs.h"

extern int _IS_FIBERFS_TEST;

void
fbr_sleep_ms(double ms)
{
	assert(ms >= 0);
	if (ms == 0) {
		return;
	}

	struct timespec tspec, rem;

	tspec.tv_sec = (time_t)(ms / 1000);
	tspec.tv_nsec = ((time_t)(ms * 1000L * 1000L)) % (1000L * 1000L * 1000L);

	errno = 0;
	while (nanosleep(&tspec, &rem) && errno == EINTR) {
		tspec.tv_sec = rem.tv_sec;
		tspec.tv_nsec = rem.tv_nsec;
		errno = 0;
	}
}

double
fbr_get_time(void)
{
	struct timespec ts;
	assert_zero(clock_gettime(CLOCK_REALTIME, &ts));

	return (double)ts.tv_sec + ((double)ts.tv_nsec / (1000 * 1000 * 1000));
}

void
fbr_timespec_add_clock(struct timespec *value)
{
	assert(value);

	struct timespec now;
	assert_zero(clock_gettime(CLOCK_REALTIME, &now));

	long ns = 1000L * 1000L * 1000L;

	value->tv_nsec += now.tv_nsec;
	assert_dev(value->tv_nsec / ns <= 1);
	value->tv_sec += value->tv_nsec / ns;
	value->tv_sec += now.tv_sec;
	value->tv_nsec %= ns;
	assert_dev(value->tv_nsec < ns);
}

unsigned long
fbr_parse_ulong(const char *str, size_t length)
{
	assert(str);
	assert(length);

	char *end;
	unsigned long ret = strtol(str, &end, 10);

	if ((ret == ULONG_MAX && errno == ERANGE ) || end != str + length) {
		return 0;
	}

	return ret;
}

// This compiles out code if we are a release build
int
fbr_is_dev(void)
{
#ifdef FBR_NO_ASSERT_DEV
	return 0;
#else
	return 1;
#endif
}

// This checks if we are running under a fiber_test context
int
fbr_is_test(void)
{
	if (_IS_FIBERFS_TEST) {
		return 1;
	}

	return 0;
}
