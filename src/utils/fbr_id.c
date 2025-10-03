/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <errno.h>
#include <limits.h>
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
fbr_id_string(fbr_id_t id, char *buffer, size_t buffer_len)
{
	assert(id);
	assert(buffer);
	assert(buffer_len >= FBR_ID_STRING_MAX);

	struct fbr_id _id;
	_id.value = id;

	fbr_id_part_t rand = _id.parts.full_random;
	fbr_id_part_t timestamp = _id.parts.timestamp;

	size_t ret = fbr_snprintf(buffer, buffer_len, FBR_ID_PRINTF_FMT, timestamp, rand);

	return ret;
}

fbr_id_t
fbr_id_parse(const char *buffer, size_t buffer_len)
{
	assert(buffer);

	if (buffer_len == 0 || buffer_len >= FBR_ID_STRING_MAX) {
		return 0;
	}

	char part[FBR_ID_PART_CHAR_MAX + 1];
	size_t offset = 0;
	size_t len = buffer_len;

	if (buffer_len > FBR_ID_PART_CHAR_MAX) {
		offset = buffer_len - FBR_ID_PART_CHAR_MAX;
		len = FBR_ID_PART_CHAR_MAX;
	}

	assert(len < sizeof(part));
	memcpy(part, buffer + offset, len);
	part[len] = '\0';

	if (strlen(part) != len) {
		return 0;
	}

	char *end;
	errno = 0;
	unsigned long rand = strtoul(part, &end, 10);

	if (rand > UINT_MAX || errno == ERANGE || *end != '\0') {
		return 0;
	}

	struct fbr_id id;
	fbr_ZERO(&id);
	id.parts.full_random = rand;

	if (buffer_len > FBR_ID_PART_CHAR_MAX) {
		len = buffer_len - FBR_ID_PART_CHAR_MAX;
		assert(len < sizeof(part));
		memcpy(part, buffer, len);
		part[len] = '\0';
	} else {
		return id.value;
	}

	if (strlen(part) != len) {
		return 0;
	}

	errno = 0;
	unsigned long timestamp = strtoul(part, &end, 10);

	if (timestamp > FBR_ID_TIMEBITS_MAX || errno == ERANGE || *end != '\0') {
		return 0;
	}

	id.parts.timestamp = timestamp;

	return id.value;
}
