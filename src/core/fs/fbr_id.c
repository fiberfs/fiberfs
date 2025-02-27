/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "fiberfs.h"
#include "fbr_id.h"

fbr_id_t
fbr_id_gen(void)
{
	struct timespec ts;
        assert_zero(clock_gettime(CLOCK_REALTIME, &ts));

	struct fbr_id id;
	id.parts.timestamp = ts.tv_sec % FBR_ID_TIMEBITS_MAX;
	id.parts.random_parts.random = random() % FBR_ID_RANDBITS_MAX;
	id.parts.random_parts.other = ts.tv_nsec % FBR_ID_OTHERBITS_MAX;

	return id.value;
}

size_t
fbr_id_string(fbr_id_t value, char *buffer, size_t buffer_len)
{
	assert(value);
	assert(buffer);
	assert(buffer_len);

	struct fbr_id id;
	id.value = value;

	fbr_id_part_t rand = id.parts.full_random;
	fbr_id_part_t timestamp = id.parts.timestamp;

	int ret = snprintf(buffer, buffer_len, "%u-%u", timestamp, rand);

	if (ret < 0 || (size_t)ret >= buffer_len) {
		return 0;
	}

	return (size_t)ret;
}
