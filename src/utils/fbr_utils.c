/*
 * Copyright (c) 2024 FiberFS
 * All rights reserved.
 *
 */

#include <errno.h>
#include <time.h>

#include "fiberfs.h"

void
fbr_sleep_ms(double ms)
{
	struct timespec tspec, rem;

	tspec.tv_sec = (time_t)(ms / 1000);
	tspec.tv_nsec = ((time_t)(ms * 1000 * 1000)) % (1000 * 1000 * 1000);

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
