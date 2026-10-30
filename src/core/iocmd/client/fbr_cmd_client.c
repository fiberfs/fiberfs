/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "fiberfs.h"
#include "core/iocmd/fbr_cmd.h"

struct _cmd_params {
	struct {
		fbr_bitflag_t		ping;
		fbr_bitflag_t		import;
		fbr_bitflag_t		force;
		fbr_bitflag_t		merge;

		fbr_bitflag_t		force_ok;
	} commands;

	int				arg_count;
	char				**args;
};

static void _cmd_usage(void);

static int
_main_ping(struct _cmd_params *cmd_params)
{
	assert_dev(cmd_params);

	if (cmd_params->arg_count != 1) {
		fprintf(stderr, "Incorrect ping usage\n");
		_cmd_usage();
		return 1;
	}

	double timing;
	int ret = fbr_cmd_ping(cmd_params->args[0], &timing);

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
_main_import(struct _cmd_params *cmd_params)
{
	assert_dev(cmd_params);

	if (!cmd_params->arg_count) {
		fprintf(stderr, "Incorrect import usage\n");
		_cmd_usage();
		return 1;
	}

	int error = 0;

	for (int i = 0; i < cmd_params->arg_count; i++) {
		printf("Importing: '%s' ...", cmd_params->args[i]);
		fflush(stdout);

		int ret = fbr_cmd_import(cmd_params->args[i], cmd_params->commands.force);

		if (ret < 0) {
			printf(" FAILED: FiberFS not detected (%d)\n", ret);
			error = 1;
		} else if (ret) {
			printf(" FAILED: %s (%d)\n", strerror(ret), ret);
			error = 1;
		} else {
			printf(" SUCCESS\n");
		}
	}

	return error;
}

static int
_main_merge(struct _cmd_params *cmd_params)
{
	assert_dev(cmd_params);

	if (cmd_params->arg_count != 1) {
		fprintf(stderr, "Incorrect merge usage\n");
		_cmd_usage();
		return 1;
	} else if (!cmd_params->commands.force) {
		fprintf(stderr, "Warning, force switch required on S3\n");
		_cmd_usage();
		return 1;
	}

	int ret = fbr_cmd_merge(cmd_params->args[0]);

	if (ret < 0) {
		fprintf(stderr, "Merge ERROR: FiberFS not detected (%d)\n", ret);
		return ret;
	} else if (ret) {
		fprintf(stderr, "Merge ERROR: %s (%d)\n", strerror(ret), ret);
		return ret;
	}

	printf("Merge SUCCESS: '%s'\n", cmd_params->args[0]);

	return 0;
}

static void
_cmd_usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  Import files:\n");
	fprintf(stderr, "    fiberfs -i [-f] <file>...\n");
	fprintf(stderr, "      -i, --import    Import file(s).\n");
	fprintf(stderr, "      -f, --force     Overwrite if file exists (optional).\n");
	fprintf(stderr, "  Merge chunks:\n");
	fprintf(stderr, "    fiberfs -m <file>\n");
	fprintf(stderr, "      -m, --merge     Merge file chunks.\n");
	fprintf(stderr, "  Ping:\n");
	fprintf(stderr, "    fiberfs -p <path>\n");
	fprintf(stderr, "      -p, --ping      Ping backend via path.\n");
}

int
main(int argc, char **argv)
{
	fbr_setup_crash_signals();
	fbr_setup_stop_signals(NULL);

	struct _cmd_params cmd_params;
	fbr_zero(&cmd_params);

	static struct option fbr_options[] = {
		{"ping", no_argument, NULL, 'p'},
		{"import", no_argument, NULL, 'i'},
		{"force", no_argument, NULL, 'f'},
		{"merge", no_argument, NULL, 'm'},
		{NULL, 0, NULL, 0}
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "pifm", fbr_options, NULL)) != -1) {
		switch (opt) {
			case 'p':
				cmd_params.commands.ping = 1;
				break;
			case 'i':
				cmd_params.commands.import = 1;
				cmd_params.commands.force_ok = 1;
				break;
			case 'f':
				cmd_params.commands.force = 1;
				break;
			case 'm':
				cmd_params.commands.merge = 1;
				// TODO temporary
				cmd_params.commands.force_ok = 1;
				break;
			default:
				_cmd_usage();
				return 1;
		}
	}

	assert(argc >= optind);
	cmd_params.arg_count = argc - optind;
	cmd_params.args = &argv[optind];

	if (cmd_params.commands.ping + cmd_params.commands.import +
	    cmd_params.commands.merge != 1) {
		fprintf(stderr, "Incorrect switch usage\n");
		_cmd_usage();
		return 1;
	} else if (cmd_params.commands.force && !cmd_params.commands.force_ok) {
		fprintf(stderr, "Incorrect force usage\n");
		_cmd_usage();
		return 1;
	}

	if (cmd_params.commands.ping) {
		return _main_ping(&cmd_params);
	} else if (cmd_params.commands.import) {
		return _main_import(&cmd_params);
	} else if (cmd_params.commands.merge) {
		return _main_merge(&cmd_params);
	}

	return 1;
}

void
fbr_context_abort(int pre_abort)
{
	(void)pre_abort;
}
