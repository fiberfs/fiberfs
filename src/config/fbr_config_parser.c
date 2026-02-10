/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "fbr_config.h"

void
fbr_config_parse(struct fbr_config *config, const char *filepath)
{
	fbr_config_ok(config);
	assert(filepath);
}
