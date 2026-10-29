/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "fbr_main.h"

int
fbr_main_command(struct fbr_main_params *main_params)
{
	assert(main_params);
	assert(main_params->commands.count);

	printf("TODO\n");
	fbr_main_usage();

	return 1;
}
