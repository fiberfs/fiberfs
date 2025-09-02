/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "test/fbr_test.h"

static fbr_id_t
_id_random(void)
{
	struct fbr_id id;
	id.parts.timestamp = (random() * random() ) % FBR_ID_TIMEBITS_MAX;
	id.parts.random_parts.random = random() % FBR_ID_RANDBITS_MAX;
	id.parts.random_parts.other = random() & FBR_ID_OTHERBITS_MAX;

	if (!id.value) {
		return 1;
	}

	return id.value;
}

static void
_id_cast(fbr_id_t id)
{
	char id_string[FBR_ID_STRING_MAX];
	fbr_id_string(id, id_string, sizeof(id_string));
	fbr_id_t id_cast = fbr_id_parse(id_string, strlen(id_string));
	fbr_test_ASSERT(id == id_cast, "cast test failed %lu != %lu", id, id_cast);
}

void
fbr_cmd_test_id_assert(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	unsigned long years = FBR_ID_TIMEBITS_MAX / 3600 / 24 / 365;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_ID_TIMEBITS=%zu", FBR_ID_TIMEBITS);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_ID_TIMEBITS_MAX=%lu", FBR_ID_TIMEBITS_MAX);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_ID_TIMEBITS_MAX: %lu years", years);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_ID_RANDBITS_MAX=%lu", FBR_ID_RANDBITS_MAX);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "RAND_MAX=%d", RAND_MAX);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_id_parts)=%zu",
		sizeof(struct fbr_id_parts));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_id)=%zu",
		sizeof(struct fbr_id));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(fbr_id_t)=%zu",
		sizeof(fbr_id_t));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(fbr_id_part_t)=%zu",
		sizeof(fbr_id_part_t));

	fbr_id_t id1 = fbr_id_gen();
	fbr_id_t id2 = fbr_id_gen();
	fbr_id_t id3 = fbr_id_gen();

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fiber id: %lu", id1);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fiber id: %lu", id2);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fiber id: %lu", id3);

	char id1_string[FBR_ID_STRING_MAX];
	char id2_string[FBR_ID_STRING_MAX];
	char id3_string[FBR_ID_STRING_MAX];
	assert(fbr_id_string(id1, id1_string, sizeof(id1_string)));
	assert(fbr_id_string(id2, id2_string, sizeof(id2_string)));
	assert(fbr_id_string(id3, id3_string, sizeof(id3_string)));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id1_string=%s", id1_string);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id2_string=%s", id2_string);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id3_string=%s", id3_string);

	char now[FBR_ID_PART_CHAR_MAX + 1];
	snprintf(now, sizeof(now), "%ld", (long)fbr_get_time());
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "timestamp_=%s", now);

	fbr_id_t id1_parsed = fbr_id_parse(id1_string, strlen(id1_string));
	fbr_id_t id2_parsed = fbr_id_parse(id2_string, strlen(id2_string));
	fbr_id_t id3_parsed = fbr_id_parse(id3_string, strlen(id3_string));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id1_parsed=%lu", id1_parsed);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id2_parsed=%lu", id2_parsed);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id3_parsed=%lu", id3_parsed);

	char *end;
	double id3_double = strtod(id3_string, &end);
	fbr_id_t id3_cast = (fbr_id_t)id3_double;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id3_double=%lf", id3_double);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id3_cast__=%lu", id3_cast);

	struct fbr_id id_max;
	id_max.parts.timestamp = FBR_ID_TIMEBITS_MAX;
	id_max.parts.random_parts.random = FBR_ID_RANDBITS_MAX;
	id_max.parts.random_parts.other = FBR_ID_OTHERBITS_MAX;

	char _id_max[FBR_ID_STRING_MAX];
	int _id_max_len = snprintf(_id_max, sizeof(_id_max), "%lu", id_max.value);
	assert((size_t)_id_max_len < sizeof(_id_max));

	char id_max_string[FBR_ID_STRING_MAX];
	size_t id_max_len = fbr_id_string(id_max.value, id_max_string, sizeof(id_max_string));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id_max=%lu:%d", id_max.value, _id_max_len);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id_max_string=%s", id_max_string);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id_max_len=%zu", id_max_len);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_ID_STRING_MAX=%d", FBR_ID_STRING_MAX);

	char id_custom[FBR_ID_STRING_MAX];
	int id_custom_len = snprintf(id_custom, sizeof(id_custom), FBR_ID_PRINTF_FMT,
		(fbr_id_part_t)FBR_ID_TIMEBITS_MAX,
		(fbr_id_part_t)((FBR_ID_RANDBITS_MAX << FBR_ID_OTHERBITS) | FBR_ID_OTHERBITS_MAX));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id_custom=%s", id_custom);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id_custom_len=%d", id_custom_len);

	char rand_max[FBR_ID_PART_CHAR_MAX + 1];
	int rand_max_len = snprintf(rand_max, sizeof(rand_max), "%u", UINT32_MAX);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "rand_max=%s", rand_max);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "rand_max_len=%d", rand_max_len);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "UINT32_MAX=%u", UINT32_MAX);

	fbr_test_ASSERT(sizeof(fbr_id_part_t) * 2 == sizeof(fbr_id_t),
		"fbr_id_part_t * 2 != fbr_id_t");
	fbr_test_ASSERT(sizeof(struct fbr_id_parts) == sizeof(fbr_id_t),
		"struct fbr_id_parts != fbr_id_t");
	fbr_test_ASSERT(sizeof(struct fbr_id) == sizeof(struct fbr_id_parts),
		"struct fbr_id != struct fbr_id_parts");
	fbr_test_ASSERT(FBR_ID_FULLRANDBITS == sizeof(fbr_id_part_t) * 8,
		"FBR_ID_FULLRANDBITS != fbr_id_part_t");
	fbr_test_ASSERT(RAND_MAX >= FBR_ID_RANDBITS_MAX, "random storage is too small");
	fbr_test_ASSERT(fbr_id_gen(), "fbr_id_gen() is 0");
	fbr_test_ASSERT(fbr_id_gen() != fbr_id_gen(), "fbr_id_gen() matched");
	fbr_test_ASSERT(id_max_len == FBR_ID_STRING_MAX - 1, "FBR_ID_STRING_MAX wrong");
	fbr_test_ERROR(strcmp(id_max_string, id_custom), "max strings dont match");
	fbr_test_ASSERT(id_custom_len == FBR_ID_STRING_MAX - 1, "FBR_ID_STRING_MAX wrong");
	fbr_test_ASSERT(strcmp(id1_string, id2_string), "id1_string == id2_string");
	fbr_test_ASSERT(strcmp(id2_string, id3_string), "id2_string == id3_string");
	fbr_test_ASSERT(rand_max_len == FBR_ID_PART_CHAR_MAX, "FBR_ID_PART_CHAR_MAX wrong");
	fbr_test_ERROR(*end, "strtod(id_max_string) error (end)");
	fbr_test_ASSERT(id1 == id1_parsed, "id1 != id1_parsed");
	fbr_test_ASSERT(id2 == id2_parsed, "id2 != id2_parsed");
	fbr_test_ASSERT(id3 == id3_parsed, "id3 != id3_parsed");

	struct fbr_id id_rand1;
	fbr_ZERO(&id_rand1);
	id_rand1.parts.random_parts.random = random() % FBR_ID_RANDBITS_MAX;
	id_rand1.parts.random_parts.other = random() & FBR_ID_OTHERBITS_MAX;
	char id_rand1_string[FBR_ID_STRING_MAX];
	fbr_id_string(id_rand1.value, id_rand1_string, sizeof(id_rand1_string));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id_rand1_string=%s", id_rand1_string);
	_id_cast(id_rand1.value);

	struct fbr_id id_rand2;
	fbr_ZERO(&id_rand2);
	id_rand2.parts.timestamp = (random() * random() ) % FBR_ID_TIMEBITS_MAX;
	char id_rand2_string[FBR_ID_STRING_MAX];
	fbr_id_string(id_rand2.value, id_rand2_string, sizeof(id_rand2_string));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id_rand2_string=%s", id_rand2_string);
	_id_cast(id_rand2.value);

	_id_cast(1);
	_id_cast(-1);
	_id_cast((random() % 1000) + 1);
	_id_cast((random() % 1000000) + 1);
	_id_cast(random() + 1);

	for (size_t i = 0; i < 10; i++) {
		_id_cast(_id_random());
	}
}
