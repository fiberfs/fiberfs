/*
 * Copyright (c) 2024 FiberFS
 * All rights reserved.
 *
 */

#include <errno.h>
#include <time.h>

#include "fiberfs.h"

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

double
fbr_get_time(void)
{
	struct timespec ts;

        assert_zero(clock_gettime(CLOCK_REALTIME, &ts));

        return ts.tv_sec + ((double)ts.tv_nsec / (1000 * 1000 * 1000));
}

unsigned long
fbr_safe_add(unsigned long *dest, unsigned long value)
{
        assert(dest);

        return __sync_add_and_fetch(dest, value);
}

unsigned long
fbr_safe_sub(unsigned long *dest, unsigned long value)
{
        assert(dest);

        return __sync_sub_and_fetch(dest, value);
}
