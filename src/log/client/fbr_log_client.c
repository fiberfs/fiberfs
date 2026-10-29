/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "log/fbr_log.h"

#define FBR_LOG_CLIENT_MAX_SLEEP_MS		25

static int _STOP;

static void
_log_signal_stop(int signal, siginfo_t *info, void *ucontext)
{
	(void)info;
	(void)ucontext;

	fprintf(stderr, "Caught signal: %s (%d)\n", strsignal(signal), signal);

	_STOP = 1;
}

static void
_usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  fiberfs_log [-d] <mount_point>\n");
	fprintf(stderr, "    -d, --dump-history    Dump log history and exit (optional).\n");
}

int
main(int argc, char **argv)
{
	fbr_setup_crash_signals();
	fbr_setup_stop_signals(_log_signal_stop);

	const char *mount_path = NULL;
	int dump_history = 0;

	int opt;
	static struct option log_options[] = {
		{"dump-history", no_argument, NULL, 'd'},
		{NULL, 0, NULL, 0}
	};

	while ((opt = getopt_long(argc, argv, "d", log_options, NULL)) != -1) {
		switch (opt) {
			case 'd':
				dump_history = 1;
				break;
			default:
				_usage();
				return 1;
		}
	}

	for (int i = optind; i < argc; i++) {
		if (!mount_path) {
			mount_path = argv[i];
		} else {
			_usage();
			return 1;
		}
	}
	if (!mount_path) {
		_usage();
		return 1;
	}

	struct fbr_log_reader _reader;
	struct fbr_log_reader *reader = &_reader;
	unsigned long sleep_ms = 0;

	int ret = fbr_log_reader_init(reader, mount_path);
	if (!ret) {
		fprintf(stderr, "Cannot open log for %s (%s)\n", mount_path, strerror(errno));
		return 1;
	}

	// TODO we should make sure we dont go past the current segment
	reader->cursor.rewind = dump_history;

	while (!_STOP) {
		char log_buffer[FBR_LOGLINE_MAX_LENGTH];
		struct fbr_log_line *log_line;

		log_line = fbr_log_reader_get(reader, log_buffer, sizeof(log_buffer));

		if (!log_line) {
			if (reader->cursor.status == FBR_LOG_CURSOR_EXIT) {
				fprintf(stderr, "Shutdown detected\n");
				break;
			} else if (reader->cursor.status == FBR_LOG_CURSOR_OVERRUN) {
				fprintf(stderr, "ERROR overrun, "
					"cannot read or print fast enough\n");
				break;
			}

			fbr_ASSERT(reader->cursor.status == FBR_LOG_CURSOR_EOF,
				"cursor.status=%d", reader->cursor.status);

			if (dump_history) {
				break;
			}

			fbr_sleep_ms(sleep_ms);

			if (sleep_ms < FBR_LOG_CLIENT_MAX_SLEEP_MS) {
				sleep_ms++;
			}

			continue;
		}

		assert(reader->cursor.status == FBR_LOG_CURSOR_OK);

		sleep_ms = 0;

		char reqid_str[32];
		fbr_log_reqid_str(log_line->request_id, reqid_str, sizeof(reqid_str));

		const char *type_str = fbr_log_type_string(reader->cursor.tag.parts.class_data);

		printf("%.3f %s:%s %s\n", log_line->timestamp, reqid_str, type_str,
			log_line->buffer);
	}

	fbr_log_reader_free(reader);

	return 0;
}

void
fbr_context_abort(int pre_abort)
{
	(void)pre_abort;
}
