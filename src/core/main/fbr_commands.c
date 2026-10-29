/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_main.h"
#include "core/iocmd/fbr_cmd.h"

static int
_main_ping(struct fbr_main_params *main_params)
{
	assert_dev(main_params);

	if (main_params->arg_count != 1) {
		fprintf(stderr, "Incorrect ping usage\n");
		fbr_main_usage();
		return 1;
	}

	double timing;
	int ret = fbr_cmd_ping(main_params->args[0], &timing);

	if (ret < 0) {
		fprintf(stderr, "Ping ERROR: FiberFS not detected (%d)\n", ret);
		return ret;
	} else if (ret) {
		fprintf(stderr, "Ping ERROR: %s (%d)\n", strerror(ret), ret);
		return ret;
	}

	printf("Ping SUCCESS: %fs\n", timing);

	return 0;
}

static int
_main_import(struct fbr_main_params *main_params)
{
	assert_dev(main_params);

	if (!main_params->arg_count) {
		fprintf(stderr, "Incorrect import usage\n");
		fbr_main_usage();
		return 1;
	}

	for (int i = 0; i < main_params->arg_count; i++) {
		printf("import: '%s'\n", main_params->args[i]);
	}

	return 1;
}

int
fbr_main_command(struct fbr_main_params *main_params)
{
	assert(main_params);
	assert(main_params->commands.count);

	if (main_params->commands.ping + main_params->commands.import != 1) {
		fprintf(stderr, "Incorrect switch usage\n");
		fbr_main_usage();
		return 1;
	} else if (main_params->commands.force && !main_params->commands.import) {
		fprintf(stderr, "Incorrect force usage\n");
		fbr_main_usage();
		return 1;
	}

	if (main_params->commands.ping) {
		return _main_ping(main_params);
	} else if (main_params->commands.import) {
		return _main_import(main_params);
	}

	return 1;
}
