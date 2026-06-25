/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "log/fbr_log.h"
#include "utils/fbr_sys.h"

static int _STOP;

static void
_log_signal_stop(int signal, siginfo_t *info, void *ucontext)
{
	(void)info;
	(void)ucontext;

	printf("Caught signal: %s (%d)\n", strsignal(signal), signal);

	_STOP = 1;
}

static void
_usage(void)
{
	printf("Usage: fiberfs_log MOUNT_PATH\n");
}

int
main(int argc, char **argv)
{
	if (argc != 2) {
		_usage();
		return 1;
	}

	fbr_setup_crash_signals();
	fbr_setup_stop_signals(_log_signal_stop);

	const char *mount_path = argv[1];

	if (!fbr_sys_isdir(mount_path)) {
		_usage();
		fprintf(stderr, "ERROR: mount not found '%s'\n", mount_path);
		return 1;
	}

	struct fbr_log_reader _reader;
	struct fbr_log_reader *reader = &_reader;

	fbr_log_reader_init(reader, mount_path);
	fbr_log_reader_ok(reader);
	fbr_log_ok(&reader->log);
	fbr_log_header_ok(reader->log.header);

	char log_buffer[FBR_LOGLINE_MAX_LENGTH];
	unsigned long sleep_ms = 0;

	while (!_STOP) {
		struct fbr_log_line *log_line;

		log_line = fbr_log_reader_get(reader, log_buffer, sizeof(log_buffer));

		if (!log_line) {
			if (reader->cursor.status == FBR_LOG_CURSOR_EXIT) {
				printf("Shutdown detected\n");
				break;
			} else if (reader->cursor.status == FBR_LOG_CURSOR_OVERFLOW) {
				printf("ERROR overflow, cannot read or print fast enough\n");
				break;
			}

			fbr_ASSERT(reader->cursor.status == FBR_LOG_CURSOR_EOF,
				"cursor.status=%d", reader->cursor.status);

			fbr_sleep_ms(sleep_ms);

			if (sleep_ms < 25) {
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
