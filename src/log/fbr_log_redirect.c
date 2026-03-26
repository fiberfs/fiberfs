/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#include "fiberfs.h"
#include "core/request/fbr_request.h"
#include "core/request/fbr_rlog.h"

struct _log_redirect {
	pthread_mutex_t		lock;
	pthread_t		thread;

	int			active;
	int			closed;

	int			fd;
	int			pfd;
	int			ofd;

	FILE			*flushd;
} _LOG_STDERR = {
	PTHREAD_MUTEX_INITIALIZER,
	0, 0, 0, 0, 0, 0, NULL
};

static void *
_log_redirector(void *arg)
{
	struct _log_redirect *redirect = arg;
	assert(redirect->active == 1);

	int fd = redirect->pfd;
	assert(fd >= 0);

	fbr_thread_name("log_redir");

	// TODO we can optionally allocate a request here and buffer

	char buffer[4096];
	ssize_t buffer_len;
	while ((buffer_len = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
		assert_dev((size_t)buffer_len < sizeof(buffer));
		buffer[buffer_len] = '\0';

		char *line = buffer;
		char *pos = buffer;
		while (*pos) {
			if (*pos == '\n') {
				*pos = '\0';
				fbr_rlog(FBR_LOG_STDERR, "%s", line);

				line = pos + 1;
			}

			pos++;
		}

		if (line < buffer + buffer_len) {
			fbr_rlog(FBR_LOG_STDERR, "%s", line);
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
	assert(redirect->fd > STDIN_FILENO);

	int pfd[2];
	int ret = pipe(pfd);
	assert_zero(ret);
	assert(pfd[0] >= 0);
	assert(pfd[1] >= 0);

	redirect->ofd = dup(redirect->fd);

	fflush(redirect->flushd);

	ret = dup2(pfd[1], redirect->fd);
	assert(ret >= 0);
	assert_zero(close(pfd[1]));

	redirect->pfd = pfd[0];

	pt_assert(pthread_create(&redirect->thread, NULL, _log_redirector, redirect));
}

static void
_log_restore(struct _log_redirect *redirect)
{
	assert(redirect);
	assert(redirect->active == 1);

	pt_assert(pthread_mutex_lock(&redirect->lock));

	if (!redirect->active || redirect->closed) {
		pt_assert(pthread_mutex_unlock(&redirect->lock));
		return;
	}

	assert(redirect->active == 1);
	redirect->closed = 1;

	fflush(redirect->flushd);

	int ret = dup2(redirect->ofd, redirect->fd);
	assert(ret >= 0);

	assert_zero(close(redirect->ofd));

	pt_assert(pthread_mutex_unlock(&redirect->lock));

	// Note: this can be called on the abort path
	if (redirect->thread != pthread_self()) {
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

	_log_redirect(&_LOG_STDERR);
}

void
fbr_log_restore_stderr(void)
{
	if (_LOG_STDERR.active) {
		assert_dev(_LOG_STDERR.fd == STDERR_FILENO);
	}

	_log_restore(&_LOG_STDERR);
}
