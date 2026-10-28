/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

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
fbr_usage(void)
{
	printf("Usage: fiberfs CONFIG MOUNT_PATH\n");
}

int
main(int argc, char **argv)
{
	fbr_setup_crash_signals();
	fbr_setup_stop_signals(_main_stop_signal);

	if (argc != 3) {
		fbr_usage();
		return 1;
	}

	return fiberfs_mount(argv[1], argv[2]);
}
