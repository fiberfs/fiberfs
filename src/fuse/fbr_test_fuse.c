/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdio.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fuse_lowlevel.h"

static void
_test_init(void *userdata, struct fuse_conn_info *conn)
{
	assert_zero(userdata);
	assert(conn);

	printf("ZZZ init called\n");
}

static const struct fuse_lowlevel_ops _test_ops = {
	.init = _test_init
};

int
fbr_fuse_test_mount(void)
{
	struct fuse_args fargs;
	struct fuse_session *session;
	char *argv[4];
	int ret;

	//fuse_cmdline_help();
	//fuse_lowlevel_help();

	fargs.argv = argv;
	fargs.argv[0] = "fiberfs";
	fargs.argv[1] = "-o";
	fargs.argv[2] = "fsname=fiberfs";
	fargs.argv[3] = "-d";
	fargs.argc = sizeof(argv) / sizeof(*argv);
	fargs.allocated = 0;

	session = fuse_session_new(&fargs, &_test_ops, sizeof(_test_ops), NULL);

	if (!session) {
		fuse_opt_free_args(&fargs);
		return 1;
	}

	ret = fuse_set_signal_handlers(session);

	if (ret) {
		fuse_session_destroy(session);
		fuse_opt_free_args(&fargs);
		return 1;
	}

	ret = fuse_session_mount(session, "/tmp/fuse1");

	if (ret) {
		fuse_remove_signal_handlers(session);
		fuse_session_destroy(session);
		fuse_opt_free_args(&fargs);
		return 1;
	}

	fuse_session_unmount(session);
	fuse_remove_signal_handlers(session);
	fuse_session_destroy(session);
	fuse_opt_free_args(&fargs);

	return 0;
}
