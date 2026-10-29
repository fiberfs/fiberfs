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

	fprintf(stderr, "Caught signal: %s (%d)\n", strsignal(signal), signal);

	FBR_MAIN_STOP = 1;
}

void
fbr_main_usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  Mount a filesystem:\n");
	fprintf(stderr, "    fiberfs <config> <mount_point>\n");
}

int
main(int argc, char **argv)
{
	fbr_setup_crash_signals();
	fbr_setup_stop_signals(_main_stop_signal);

	static struct option fbr_options[] = {
		{NULL, 0, NULL, 0}
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "", fbr_options, NULL)) != -1) {
		switch (opt) {
			default:
				fbr_main_usage();
				return 1;
		}
	}

	assert(argc >= optind);
	int arg_count = argc - optind;
	char **args = &argv[optind];

	if (arg_count != 2) {
		fbr_main_usage();
		return 1;
	}

	return fiberfs_mount(args[0], args[1]);
}
