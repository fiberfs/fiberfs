/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "fiberfs.h"
#include "core/fuse/fbr_fuse.h"
#include "log/fbr_log.h"

int _FBR_LOG_REDIRECTOR_HAS_FORK;

struct _log_redirect {
	pthread_mutex_t		lock;
	pthread_t		thread;

	int			active;
	int			closed;

	int			fd;
	int			pfd;
	int			ofd;

	FILE			*flushd;

	enum fbr_log_type	log_type;
} _LOG_STDERR = {
	PTHREAD_MUTEX_INITIALIZER,
	0, 0, 0, 0, 0, 0, NULL, 0
};

static void *
_log_redirector(void *arg)
{
	struct _log_redirect *redirect = arg;
	assert(redirect->active == 1);
	assert_dev(redirect->log_type);

	int fd = redirect->pfd;
	assert(fd >= 0);

	fbr_thread_name("log_redir");

	// TODO we can optionally allocate a request here and buffer

	assert(fbr_fuse_has_context());
	struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
	struct fbr_log *log = fuse_ctx->log;
	fbr_log_ok(log);

	char buffer[4096];
	ssize_t buffer_len;

	while ((buffer_len = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
		assert_dev((size_t)buffer_len < sizeof(buffer));
		buffer[buffer_len] = '\0';

		char *line = buffer;
		size_t line_len = 0;

		while (line[line_len]) {
			if (line[line_len] == '\n') {
				line[line_len] = '\0';

				if (line_len) {
					fbr_log_print(log, redirect->log_type, FBR_REQID_CORE,
						"%s", line);
				}

				line += line_len + 1;
				line_len = 0;

				continue;
			}

			line_len++;
		}

		if (line_len) {
			fbr_log_print(log, redirect->log_type, FBR_REQID_CORE, "%s", line);
		}
	}

	assert_zero(buffer_len);
	assert(redirect->closed);
	assert_zero(close(fd));

	return NULL;
}

static void
_log_redirect(struct _log_redirect *redirect)
{
	assert(redirect);
	assert(redirect->active == 1);
	assert(redirect->fd > STDOUT_FILENO);

	int pfd[2];
	int ret = pipe(pfd);
	assert_zero(ret);
	assert(pfd[0] >= 0);
	assert(pfd[1] >= 0);

	redirect->ofd = dup(redirect->fd);

	assert_dev(redirect->flushd);
	fflush(redirect->flushd);

	ret = dup2(pfd[1], redirect->fd);
	assert(ret >= 0);
	assert_zero(close(pfd[1]));

	redirect->pfd = pfd[0];

	pt_assert(pthread_create(&redirect->thread, NULL, _log_redirector, redirect));
}

// Note: this is used in the abort path
static void
_log_restore(struct _log_redirect *redirect)
{
	assert(redirect);

	pt_assert(pthread_mutex_lock(&redirect->lock));

	if (!redirect->active || redirect->closed) {
		pt_assert(pthread_mutex_unlock(&redirect->lock));
		return;
	}

	assert(redirect->active == 1);
	redirect->closed = 1;

	pt_assert(pthread_mutex_unlock(&redirect->lock));

	assert_dev(redirect->flushd);
	fflush(redirect->flushd);

	int ret = dup2(redirect->ofd, redirect->fd);
	assert(ret >= 0);

	assert_zero(close(redirect->ofd));

	// Prevent abort deadlock
	if (redirect->thread != pthread_self() && !_FBR_LOG_REDIRECTOR_HAS_FORK) {
		pt_assert(pthread_join(redirect->thread, NULL));
	}
}

void
fbr_log_redirect_stderr(void)
{
	assert_zero(_LOG_STDERR.active);
	assert_zero(_LOG_STDERR.fd);

	_LOG_STDERR.active = 1;
	_LOG_STDERR.fd = STDERR_FILENO;
	_LOG_STDERR.flushd = stderr;
	_LOG_STDERR.log_type = FBR_LOG_STDERR;

	_log_redirect(&_LOG_STDERR);
}

// Note: this is used in the abort path
void
fbr_log_restore_stderr(void)
{
	_log_restore(&_LOG_STDERR);
}
