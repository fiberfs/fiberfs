/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "core/fs/fbr_fs.h"
#include "test/fbr_test.h"

void
fbr_cmd_fs_test_id_assert(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	unsigned long years = FBR_ID_TIMEBITS_MAX / 3600 / 24 / 365;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_ID_TIMEBITS=%d", FBR_ID_TIMEBITS);
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

	struct timespec now;
	assert_zero(clock_gettime(CLOCK_REALTIME, &now));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_ID_BASETIME=%d", FBR_ID_BASETIME);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "now.tv_sec=%lu", now.tv_sec);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fiber time: %lu", now.tv_sec - FBR_ID_BASETIME);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fiber id: %lu", fbr_id_gen());
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fiber id: %lu", fbr_id_gen());
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fiber id: %lu", fbr_id_gen());

	char id1_string[FBR_ID_STRING_MAX];
	char id2_string[FBR_ID_STRING_MAX];
	char id3_string[FBR_ID_STRING_MAX];
	assert(fbr_id_string(fbr_id_gen(), id1_string, sizeof(id1_string)));
	assert(fbr_id_string(fbr_id_gen(), id2_string, sizeof(id2_string)));
	assert(fbr_id_string(fbr_id_gen(), id3_string, sizeof(id3_string)));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id1_string=%s", id1_string);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id2_string=%s", id2_string);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id3_string=%s", id3_string);

	struct fbr_id id_max;
	id_max.parts.timestamp = FBR_ID_TIMEBITS_MAX;
	id_max.parts.random = FBR_ID_RANDBITS_MAX;

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
	int id_custom_len = snprintf(id_custom, sizeof(id_custom), "%lu-%lu",
		FBR_ID_TIMEBITS_MAX, FBR_ID_RANDBITS_MAX);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id_custom=%s", id_custom);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "id_custom_len=%d", id_custom_len);

	fbr_test_ASSERT(sizeof(struct fbr_id_parts) == sizeof(fbr_id_t),
		"struct fbr_id_parts != fbr_id_t");
	fbr_test_ASSERT(sizeof(struct fbr_id) == sizeof(struct fbr_id_parts),
		"struct fbr_id != struct fbr_id_parts");
	fbr_test_ASSERT(now.tv_sec > FBR_ID_BASETIME, "FBR_ID_BASETIME is too high");
	fbr_test_ASSERT(years > 250, "Not enough years available");
	fbr_test_ASSERT(FBR_ID_RANDBITS_MAX > (1000 * 1000 * 1000), "random is too small");
	fbr_test_ASSERT(RAND_MAX >= FBR_ID_RANDBITS_MAX, "random storage is too small");
	fbr_test_ASSERT(fbr_id_gen(), "fbr_id_gen() is 0");
	fbr_test_ASSERT(fbr_id_gen() != fbr_id_gen(), "fbr_id_gen() matched");
	fbr_test_ASSERT(id_max_len == FBR_ID_STRING_MAX - 1, "FBR_ID_STRING_MAX wrong");
	fbr_test_ERROR(strcmp(id_max_string, id_custom), "max strings dont match");
	fbr_test_ASSERT(id_custom_len == FBR_ID_STRING_MAX - 1, "FBR_ID_STRING_MAX wrong");
	fbr_test_ASSERT(strcmp(id1_string, id2_string), "id1_string == id2_string");
	fbr_test_ASSERT(strcmp(id2_string, id3_string), "id2_string == id3_string");
}
