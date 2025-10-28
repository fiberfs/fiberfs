/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <unistd.h>

#include "fiberfs.h"
#include "chttp.h"
#include "cstore/fbr_cstore_api.h"
#include "utils/fbr_sys.h"

size_t
fbr_cstore_s3_splice_out(struct fbr_cstore *cstore, struct chttp_addr *addr, int fd_in,
    size_t size)
{
	fbr_cstore_ok(cstore);
	chttp_addr_connected(addr)
	assert(fd_in >= 0);
	assert(size);

	size_t bytes = 0;
	off_t offset = 0;
	int error = 0;
	int fallback_rw = 0;
	if (cstore->cant_splice_out) {
		fallback_rw = 1;
	}

	while (!fallback_rw && bytes < size) {
		ssize_t ret = sendfile(addr->sock, fd_in, &offset, size - bytes);
		if (ret <= 0) {
			if (!ret) {
				break;
			} else if (bytes == 0 && (errno == EINVAL || errno == ENOSYS)) {
				fbr_rlog(FBR_LOG_CS_S3, "Cannot splice out, falling back");
				cstore->cant_splice_out = 1;
				fallback_rw = 1;
			} else {
				error = errno;
			}
			break;
		}

		bytes += (size_t)ret;
	}

	while (fallback_rw && bytes < size) {
		char buffer[FBR_CSTORE_IO_SIZE];
		ssize_t ret = read(fd_in, buffer, sizeof(buffer));
		if (ret <= 0) {
			if (ret < 0) {
				error = errno;
			}
			break;
		}

		chttp_tcp_send(addr, buffer, ret);
		if (addr->error) {
			error = addr->error;
			break;
		}

		bytes += (size_t)ret;
	}

	fbr_rlog(FBR_LOG_CS_S3, "SPLICE_OUT wrote %zu bytes (%s) error: %d", bytes,
		fallback_rw ? "read/write" : "sendfile", error);

	// Caller will cleanup since it knows the expected byte count

	return bytes;
}

size_t
fbr_cstore_s3_splice_in(struct fbr_cstore *cstore, struct chttp_context *http, int fd_out,
    size_t size)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(http);
	assert(http->state == CHTTP_STATE_BODY);
	assert(fd_out >= 0);

	size_t bytes = 0;
	int error = 0;
	int fallback_rw = 0;
	if (cstore->cant_splice_in || http->chunked || !size) {
		fallback_rw = 1;
	}

	// TODO for large bodies, drain the dpage, then splice
	if (!fallback_rw) {
		size_t buffered = chttp_body_buffered(http);
		assert(size >= buffered);
		size_t unbuffered = size - buffered;

		fbr_rlog(FBR_LOG_CS_S3, "SPLICE_IN buffering detected bytes: %zu remaining: %zu",
			buffered, unbuffered);

		if (buffered) {
			fallback_rw = 1;
		}
	}

	int pipe_ret = 1;
	int pipefd[2];
	if (!fallback_rw) {
		assert(size == (size_t)http->length);
		pipe_ret = pipe(pipefd);
		if (pipe_ret < 0) {
			fallback_rw = 1;
		}
	}

	while (!fallback_rw && bytes < size) {
		ssize_t pipe_bytes = splice(http->addr.sock, NULL, pipefd[1], NULL, size - bytes,
			SPLICE_F_MOVE);
		if (pipe_bytes < 0) {
			if (bytes == 0 && (errno == EINVAL || errno == ENOSYS)) {
				fbr_rlog(FBR_LOG_CS_S3, "Cannot splice in, falling back");
				cstore->cant_splice_in = 1;
				fallback_rw = 1;
			} else {
				chttp_error(http, CHTTP_ERR_RESP_BODY);
				error = errno;
			}
			break;
		} else if (!pipe_bytes) {
			chttp_error(http, CHTTP_ERR_RESP_BODY);
			break;
		}

		ssize_t out_bytes = 0;
		while (out_bytes < pipe_bytes) {
			ssize_t ret = splice(pipefd[0], NULL, fd_out, NULL, pipe_bytes - out_bytes,
				SPLICE_F_MOVE);
			if (ret <= 0) {
				chttp_error(http, CHTTP_ERR_RESP_BODY);
				if (ret < 0) {
					error = errno;
				}
				break;
			}

			out_bytes += (size_t)ret;
		}

		if (pipe_bytes != out_bytes) {
			chttp_error(http, CHTTP_ERR_RESP_BODY);
			break;
		}

		bytes += (size_t)out_bytes;
	}

	if (!pipe_ret) {
		assert_zero(close(pipefd[0]));
		assert_zero(close(pipefd[1]));
	}

	while (fallback_rw && (!size || bytes < size)) {
		char buffer[FBR_CSTORE_IO_SIZE];
		size_t ret = chttp_body_read(http, buffer, sizeof(buffer));
		if (http->error) {
			break;
		} else if (ret == 0) {
			break;
		}

		ret = fbr_sys_write(fd_out, buffer, ret);
		if (ret == 0) {
			chttp_error(http, CHTTP_ERR_RESP_BODY);
			break;
		}

		bytes += (size_t)ret;
	}

	if (!fallback_rw && !http->error) {
		http->length = 0;
		http->state = CHTTP_STATE_IDLE;
	}

	fbr_rlog(FBR_LOG_CS_S3, "SPLICE_IN wrote %zu bytes (%s) error: %d chttp error: %d",
		bytes, fallback_rw ? "read/write" : "splice", error, http->error);

	return bytes;
}
