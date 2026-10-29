/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_main.h"

int FBR_MAIN_STOP;

static void
_main_stop_signal(int signal, siginfo_t *info, void *ucontext)
{
	(void)info;
	(void)ucontext;

	printf("Caught signal: %s (%d)\n", strsignal(signal), signal);

	FBR_MAIN_STOP = 1;
}

void
fbr_main_usage(void)
{
	printf("Usage: fiberfs CONFIG MOUNT_PATH\n");
}

int
main(int argc, char **argv)
{
	fbr_setup_crash_signals();
	fbr_setup_stop_signals(_main_stop_signal);

	struct fbr_main_params main_params;
	fbr_zero(&main_params);

	int opt;
	static struct option fbr_options[] = {
		{"import", no_argument, NULL, 'i'},
		{"force", no_argument, NULL, 'f'},
		{NULL, 0, NULL, 0}
	};

	while ((opt = getopt_long(argc, argv, "if", fbr_options, NULL)) != -1) {
		switch (opt) {
			case 'i':
				main_params.commands.import = 1;
				main_params.commands.count++;
				break;
			case 'f':
				main_params.commands.force = 1;
				main_params.commands.count++;
				break;
			default:
				fbr_main_usage();
				return 1;
		}
	}

	main_params.arg_count = argc;
	main_params.arg_index = optind;
	main_params.args = argv;

	if (main_params.commands.count) {
		return fbr_main_command(&main_params);
	}

	return fiberfs_mount(&main_params);
}
