/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fiberfs.h"
#include "chttp.h"
#include "cstore/fbr_cstore_api.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "utils/fbr_sys.h"

static void
_fetch_init(struct fbr_cstore_fetch_context *fetch, struct fbr_cstore *cstore,
    struct chttp_context *http)
{
	assert(fetch);
	fbr_cstore_ok(cstore);
	chttp_context_ok(http);
	assert_dev(http->state == CHTTP_STATE_NONE);

	fbr_zero(fetch);
	fetch->cstore = cstore;
	fetch->http = http;

	fbr_cstore_fetch_ok(fetch);
}

void
fbr_cstore_fetch_init(struct fbr_cstore_fetch_context *fetch, struct fbr_cstore *cstore,
    struct chttp_context *http, enum fbr_cstore_file_type type, struct fbr_cstore_path *file_path,
    fbr_id_t etag, size_t length, size_t offset, fbr_id_t existing, int gzip,
    enum fbr_cstore_route route)
{
	_fetch_init(fetch, cstore, http);

	assert(type > FBR_CSTORE_FILE_NONE && type <= FBR_CSTORE_FILE_ROOT);
	fbr_cstore_path_ok(file_path);
	assert(route > FBR_CSTORE_ROUTE_NONE && route <= FBR_CSTORE_ROUTE_S3);

	fetch->type = type;
	fetch->file_path = file_path;
	fetch->etag = etag;
	fetch->length = length;
	fetch->offset = offset;
	fetch->existing = existing;
	fetch->gzip = gzip;
	fetch->route = route;
}

static fbr_hash_t
_s3_request_url(struct fbr_cstore_fetch_context *fetch, const char *method,
    const struct fbr_cstore_url *url)
{
	assert_dev(fetch);
	assert_dev(fetch->cstore);
	assert_dev(fetch->cstore->s3.backend);
	assert_dev(fetch->http);
	assert_dev(fetch->attempts);
	assert_dev(method);
	fbr_cstore_url_ok(url);
	assert(strstr(url->value, FBR_FIBERFS_NAME));

	if (fetch->attempts > 3) {
		fbr_rlog(FBR_LOG_CS_S3, "sleep_backoff");
		fbr_sleep_backoff(fetch->attempts - 1);
	}

	if (fetch->attempts > 1) {
		fbr_stat_add(&fetch->cstore->stats.retries);
		fetch->http->new_conn = 1;
	}

	chttp_set_method(fetch->http, method);
	chttp_set_url(fetch->http, url->value);

	struct fbr_cstore_backend *s3_backend = fetch->cstore->s3.backend;
	chttp_header_add(fetch->http, "Host", s3_backend->host);

	fbr_rlog(FBR_LOG_CS_S3, "S3 %s %s (attempts: %d)", method, url->value, fetch->attempts);

	if (!strcmp(method, "GET")) {
		chttp_header_add(fetch->http, "Accept-Encoding", "gzip");
	}

	char fiber_id[32];
	fbr_cstore_request_id(fiber_id, sizeof(fiber_id));
	chttp_header_add(fetch->http, "FiberFS-ID", fiber_id);

	fbr_hash_t hash = fbr_cstore_hash_url(s3_backend->host, s3_backend->host_len, url->value,
		url->length);
	return hash;
}

static fbr_hash_t
_s3_request_path(struct fbr_cstore_fetch_context *fetch, const char *method)
{
	assert_dev(fetch);
	assert_dev(method);

	struct fbr_cstore_url url;
	fbr_cstore_s3_url(fetch->cstore, fetch->file_path, &url);

	return _s3_request_url(fetch, method, &url);
}

static int
_s3_connection(struct fbr_cstore_fetch_context *fetch, struct fbr_cstore_backend *backend,
    fbr_cstore_s3_hash_f hash_cb, void *hash_priv)
{
	assert_dev(fetch);
	assert_dev(fetch->cstore);
	assert_dev(fetch->http);
	assert_dev(backend);

	chttp_connect(fetch->http, backend->host, backend->host_len, backend->port, backend->tls);
	if (fetch->http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "S3 ERROR %s (%s %d)", backend->host,
			chttp_error_msg(fetch->http), fetch->http->error);
		return 1;
	}

	// TODO convert/merge fetch->data_callback to a hash_callback
	fbr_cstore_s3_autosign(fetch->cstore, fetch->http, hash_cb, hash_priv);

	fetch->http->addr.timeout_connect_ms = fetch->cstore->config.timeout_connect_ms;
	fetch->http->addr.timeout_transfer_ms = fetch->cstore->config.timeout_transfer_ms;

	return 0;
}

static void
_s3_send_get(struct fbr_cstore_fetch_context *fetch)
{
	fbr_cstore_fetch_ok(fetch);
	assert_dev(fetch->file_path);
	assert_dev(fetch->route);
	assert_dev(fetch->attempts);

	struct fbr_cstore *cstore = fetch->cstore;
	struct chttp_context *http = fetch->http;
	assert_dev(http->state == CHTTP_STATE_NONE);

	fbr_hash_t hash = _s3_request_path(fetch, "GET");

	if (fetch->etag) {
		char buffer[32];
		fbr_cstore_etag(fetch->etag, buffer, sizeof(buffer));
		chttp_header_add(http, "If-Match", buffer);
	}

	struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash, fetch->route,
		fetch->attempts - 1, 1);

	int ret = fbr_cstore_servers_contains(cstore, backend);
	if (ret && !cstore->debug_allow_loop) {
		fbr_rlog(FBR_LOG_CS_S3, "BACKEND self detected");
		assert(fetch->route == FBR_CSTORE_ROUTE_CLUSTER);
		backend = fbr_cstore_backend_get(cstore, hash, FBR_CSTORE_ROUTE_CDN,
			fetch->attempts - 1, 1);
	}

	fbr_cstore_backend_ok(backend);
	assert_zero_dev(http->error);

	ret = _s3_connection(fetch, backend, &fbr_cstore_s3_hash_none, NULL);
	if (ret) {
		return;
	}

	chttp_send(http);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "S3 ERROR %s (%d)", chttp_error_msg(http),
			http->error);
		return;
	}

	chttp_receive(http);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "S3 ERROR %s (%d)", chttp_error_msg(http),
			http->error);
		return;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3 response: %d", http->status);
	fbr_cstore_http_log(http);
}

void
fbr_cstore_s3_send_get(struct fbr_cstore_fetch_context *fetch)
{
	fbr_cstore_fetch_ok(fetch);
	fbr_cstore_path_ok(fetch->file_path);
	assert(fbr_cstore_backend_enabled(fetch->cstore));
	assert_zero(fetch->existing);
	assert(fetch->route);

	fetch->attempts = 0;
	enum fbr_cstore_route orig_route = fetch->route;

	while (fetch->attempts <= (fetch->cstore->config.retries + 1)) {
		fetch->attempts++;
		if (fetch->attempts > 1) {
			chttp_context_reset(fetch->http);
		}
		if (fetch->attempts > (fetch->cstore->config.cluster_retries + 1) &&
		    orig_route != FBR_CSTORE_ROUTE_S3) {
			if (fetch->route == orig_route) {
				fetch->route = FBR_CSTORE_ROUTE_S3;
			} else {
				fetch->route = orig_route;
			}
		}

		_s3_send_get(fetch);

		if (fetch->http->error || fetch->http->status >= 500) {
			continue;
		}

		break;
	}
}

static void
_s3_send_put(struct fbr_cstore_fetch_context *fetch)
{
	fbr_cstore_fetch_ok(fetch);
	assert_dev(fetch->file_path);
	assert(fetch->length);
	assert_dev(fetch->etag);
	assert_dev(fetch->data_callback);
	assert_dev(fetch->route);
	assert_dev(fetch->attempts);

	struct fbr_cstore *cstore = fetch->cstore;
	struct chttp_context *http = fetch->http;
	assert_dev(http->state == CHTTP_STATE_NONE);

	fbr_hash_t hash = _s3_request_path(fetch, "PUT");

	char buffer[32];
	fbr_bprintf(buffer, "%zu", fetch->length);

	chttp_header_add(http, "Content-Length", buffer);

	if (fetch->existing) {
		fbr_cstore_etag(fetch->existing, buffer, sizeof(buffer));
		chttp_header_add(http, "If-Match", buffer);
	} else {
		chttp_header_add(http, "If-None-Match", "*");
	}

	fbr_cstore_etag(fetch->etag, buffer, sizeof(buffer));
	chttp_header_add(http, "ETag", buffer);

	if (fetch->gzip) {
		chttp_header_add(http, "Content-Encoding", "gzip");
	}

	switch (fetch->type) {
		case FBR_CSTORE_FILE_INDEX:
			chttp_header_add(http, "Content-Type", "application/json");

			break;
		case FBR_CSTORE_FILE_ROOT:
			chttp_header_add(http, "Content-Type", "application/json");

			// TODO do we want to force a max-age in S3?
			// see cstore->config.root_ttl_sec
			//chttp_header_add(http, "Cache-Control", "max-age=86400");

			break;
		default:
			chttp_header_add(http, "Content-Type", "application/octet-stream");
			break;
	}

	struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash, fetch->route,
		fetch->attempts - 1, cstore->config.allow_cdn_put);

	int ret = fbr_cstore_servers_contains(cstore, backend);
	if (ret && !cstore->debug_allow_loop) {
		fbr_rlog(FBR_LOG_CS_S3, "BACKEND self detected");
		assert(fetch->route == FBR_CSTORE_ROUTE_CLUSTER);
		backend = fbr_cstore_backend_get(cstore, hash, FBR_CSTORE_ROUTE_CDN,
			fetch->attempts - 1, cstore->config.allow_cdn_put);
	}

	fbr_cstore_backend_ok(backend);
	assert_zero_dev(http->error);

	// TODO data_callback for s3 signing hash
	ret = _s3_connection(fetch, backend, NULL, NULL);
	if (ret) {
		return;
	}

	chttp_send(http);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp send");
		return;
	}

	fetch->data_callback(http, fetch->data_arg);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp body");
		return;
	}
	assert_zero(http->length);

	fbr_rlog(FBR_LOG_CS_S3, "PUT send complete, body length: %zu", fetch->length);

	chttp_receive(http);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp receive");
		return;
	}

	fbr_cstore_http_log(http);

	size_t body_len;
	do {
		char buffer[FBR_CSTORE_IO_SIZE];
		body_len = chttp_body_read(http, buffer, sizeof(buffer));
	} while (body_len);

	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp rbody");
		return;
	}
}

void
fbr_s3_send_put(struct fbr_cstore_fetch_context *fetch)
{
	fbr_cstore_fetch_ok(fetch);
	assert_dev(fetch->file_path);
	assert_dev(fetch->length);
	assert_dev(fetch->etag);
	assert_dev(fetch->data_callback);
	assert_dev(fetch->route);
	assert_dev(fbr_cstore_backend_enabled(fetch->cstore));

	fetch->attempts = 0;

	while (fetch->attempts <= (fetch->cstore->config.retries + 1)) {
		fetch->attempts++;
		if (fetch->attempts > 1) {
			chttp_context_reset(fetch->http);
		}
		if (fetch->attempts > (fetch->cstore->config.cluster_retries + 1)) {
			fetch->route = FBR_CSTORE_ROUTE_S3;
		}

		_s3_send_put(fetch);

		if (fetch->http->error || fetch->http->status >= 500) {
			continue;
		}

		break;
	}
}

int
fbr_cstore_s3_send_finish(struct fbr_cstore *cstore, struct fbr_cstore_op_sync *sync,
    struct chttp_context *http, int error)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(http);

	if (sync) {
		fbr_cstore_op_sync_wait(sync);
		if (sync->error) {
			assert_dev(http->state == CHTTP_STATE_NONE);
			error = 1;
		}

		fbr_cstore_op_sync_free(sync);
	}

	if (http->state == CHTTP_STATE_NONE) {
		chttp_context_free(http);
		return error;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3 response: %d (%d %d %s)", http->status, http->state,
		http->error, chttp_error_msg(http));

	if (http->error || http->status != 200) {
		error = http->status ? http->status : 1;
		assert_dev(error > 0);
	} else {
		error = 0;
	}

	chttp_context_free(http);

	return error;
}

int
fbr_cstore_s3_get_write(struct fbr_cstore_fetch_context *fetch, fbr_hash_t hash,
    struct fbr_cstore_entry **entry_ref)
{
	fbr_cstore_fetch_ok(fetch);
	fbr_cstore_path_ok(fetch->file_path);
	assert_dev(fetch->type);
	assert(fetch->type != FBR_CSTORE_FILE_ROOT);
	assert_dev(fetch->route);

	struct fbr_cstore *cstore = fetch->cstore;
	assert(fbr_cstore_backend_enabled(cstore));

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	fbr_rlog(FBR_LOG_CS_S3, "S3_GET %s", fetch->file_path->value);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, fetch->length,
		&hashpath, 1);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET loading state");
		return 1;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	fbr_cstore_s3_send_get(fetch);

	struct chttp_context *http = fetch->http;
	chttp_context_ok(http);

	if (http->error || http->status != 200) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET: %d %d", http->error, http->status);
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);

		int error = http->status ? http->status : 1;
		assert_dev(error > 0);
		chttp_context_free(http);

		return error;
	} else if (!http->chunked && fetch->length && (size_t)http->length != fetch->length) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET length");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		chttp_context_free(http);
		return 1;
	}

	if (!fetch->etag) {
		const char *etag = chttp_header_get(http, "ETag");
		if (!etag) {
			fbr_rlog(FBR_LOG_CS_S3, "S3_GET ERROR no id_etag");
			fbr_cstore_set_error(entry);
			fbr_cstore_remove(cstore, &entry);
			chttp_context_free(http);
			return 1;
		}

		size_t etag_len = strlen(etag);
		if (etag_len >= 2 && etag[etag_len - 1] == '\"' && etag[0] == '\"') {
			etag++;
			etag_len -= 2;
		}

		fetch->etag = fbr_id_parse(etag, etag_len);
		if (!fetch->etag) {
			fbr_rlog(FBR_LOG_CS_S3, "S3_GET ERROR bad id_etag");
			fbr_cstore_set_error(entry);
			fbr_cstore_remove(cstore, &entry);
			chttp_context_free(http);
			return 1;
		}
	}

	int fd = open(hashpath.value, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		chttp_context_free(http);
		return 1;
	}

	size_t bytes = fbr_cstore_s3_splice_in(cstore, http, fd, fetch->length);

	assert_zero(close(fd));

	if (http->error || (fetch->length && bytes != fetch->length) || !bytes) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET bytes");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		chttp_context_free(http);
		return 1;
	} else {
		assert_dev(http->state >= CHTTP_STATE_IDLE);
		assert_zero_dev(http->length);
	}

	if (!fetch->length) {
		assert_zero_dev(entry->bytes);
		fetch->length = bytes;
		if (fetch->type == FBR_CSTORE_FILE_ROOT) {
			fetch->length = FBR_CSTORE_ROOT_SIZE;
		}

		int ret = fbr_cstore_set_size(cstore, entry, fetch->length);
		if (ret) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET size");
			fbr_cstore_set_error(entry);
			fbr_cstore_remove(cstore, &entry);
			chttp_context_free(http);
			return 1;
		}
	}

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = fetch->etag;
	metadata.size = bytes;
	metadata.offset = fetch->offset;
	metadata.type = fetch->type;
	metadata.gzipped = http->gzip;
	fbr_strbcpy(metadata.path, fetch->file_path->value);

	chttp_context_free(http);

	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
	int ret = fbr_cstore_metadata_write(&hashpath, &metadata);
	if (ret) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		return 1;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3_GET done %zu bytes", bytes);

	if (entry_ref) {
		assert_zero_dev(*entry_ref);

		*entry_ref = fbr_cstore_get(cstore, hash);
		fbr_cstore_entry_ok(*entry_ref);
		assert_dev((*entry_ref)->state == FBR_CSTORE_LOADING);
	}

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, &entry);
	assert_zero_dev(entry);

	switch (fetch->type) {
		case FBR_CSTORE_FILE_CHUNK:
			fbr_stat_add(&cstore->stats.fetch_chunks);
			fbr_stat_add_count(&cstore->stats.wr_chunk_bytes, bytes);
			fbr_stat_add(&cstore->stats.wr_chunks);
			break;
		case FBR_CSTORE_FILE_INDEX:
			fbr_stat_add_count(&cstore->stats.wr_index_bytes, bytes);
			fbr_stat_add(&cstore->stats.wr_indexes);
			break;
		default:
			break;
	}

	return 0;
}

int
fbr_cstore_s3_send_delete(struct fbr_cstore *cstore, const struct fbr_cstore_url *url, fbr_id_t id,
    enum fbr_cstore_route route)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_url_ok(url);
	assert(route);
	assert(fbr_cstore_backend_enabled(cstore));

	struct fbr_cstore_fetch_context fetch;
	struct chttp_context http;

	chttp_context_init(&http);
	_fetch_init(&fetch, cstore, &http);

	fetch.attempts = 0;

	while (fetch.attempts <= (cstore->config.retries + 1)) {
		fetch.attempts++;
		if (fetch.attempts > 1) {
			chttp_context_reset(&http);
		}
		if (fetch.attempts > (cstore->config.cluster_retries + 1) ||
		    !cstore->delete_cache) {
			route = FBR_CSTORE_ROUTE_S3;
		}

		fbr_hash_t hash = _s3_request_url(&fetch, "DELETE", url);

		char buffer[32];
		fbr_cstore_etag(id, buffer, sizeof(buffer));
		chttp_header_add(&http, "If-Match", buffer);

		struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash, route,
			fetch.attempts - 1, cstore->config.allow_cdn_delete);
		fbr_cstore_backend_ok(backend);

		int ret = _s3_connection(&fetch, backend, fbr_cstore_s3_hash_none, NULL);
		if (ret) {
			continue;
		}

		chttp_send(&http);
		if (http.error) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp send: %s", chttp_error_msg(&http));
			continue;
		}

		chttp_receive(&http);
		if (http.error || http.status >= 500) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp recv: %s (%d)",
				chttp_error_msg(&http), http.status);
			continue;
		}

		fbr_cstore_http_log(&http);

		break;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3 DELETE %d %d", http.error, http.status);

	if (http.error || http.status != 200) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp: %d %d", http.error, http.status);

		int error = http.status ? http.status : 1;
		assert_dev(error > 0);

		chttp_context_free(&http);

		return error;
	}

	chttp_context_free(&http);

	return 0;
}

static void
_s3_wbuffer_data_cb(struct chttp_context *http, void *arg)
{
	chttp_context_ok(http);
	assert(arg);

	struct fbr_wbuffer *wbuffer = arg;
	fbr_wbuffer_ok(wbuffer);

	chttp_body_send(http, wbuffer->buffer, wbuffer->end);
	assert_zero(http->length);
}

void
fbr_cstore_s3_wbuffer_send(struct fbr_cstore *cstore, struct chttp_context *http,
    struct fbr_cstore_path *path, struct fbr_wbuffer *wbuffer)
{
	struct fbr_cstore_fetch_context fetch;

	fbr_cstore_fetch_init(&fetch, cstore, http, FBR_CSTORE_FILE_CHUNK, path, wbuffer->id,
		wbuffer->end, wbuffer->offset, 0, 0, FBR_CSTORE_ROUTE_CLUSTER);

	fetch.data_callback = _s3_wbuffer_data_cb;
	fetch.data_arg = wbuffer;

	fbr_s3_send_put(&fetch);
}

void
fbr_cstore_s3_wbuffer_finish(struct fbr_fs *fs, struct fbr_cstore *cstore,
    struct fbr_cstore_op_sync *sync, struct chttp_context *http, struct fbr_wbuffer *wbuffer,
    int error)
{
	fbr_fs_ok(fs);
	fbr_wbuffer_ok(wbuffer);

	error = fbr_cstore_s3_send_finish(cstore, sync, http, error);
	if (error) {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
	} else {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_DONE);
	}
}

static inline void
_s3_chunk_read_error(struct fbr_fs *fs, struct fbr_cstore *cstore, struct fbr_cstore_entry *entry,
    struct fbr_file *file, struct fbr_chunk *chunk, struct chttp_context *http)
{
	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);

	fbr_cstore_set_error(entry);
	fbr_cstore_release(cstore, &entry);

	chttp_context_free(http);
}

static inline void
_s3_chunk_readwrite_error(struct fbr_fs *fs, struct fbr_cstore *cstore,
    struct fbr_cstore_entry *entry, struct fbr_file *file, struct fbr_chunk *chunk, int async)
{
	if (async) {
		fbr_file_LOCK(fs, file);
		fbr_chunk_release(chunk);
		fbr_file_UNLOCK(file);
		fbr_inode_release(fs, &file);
	}

	fbr_cstore_set_error(entry);
	fbr_cstore_remove(cstore, &entry);
}

void
fbr_cstore_s3_chunk_read(struct fbr_fs *fs, struct fbr_cstore *cstore, struct fbr_file *file,
    struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_cstore_ok(cstore);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY || chunk->state == FBR_CHUNK_LOADING);
	assert_zero(chunk->external);

	if (!fbr_cstore_backend_enabled(cstore)) {
		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	int async = 0;
	if (chunk->state == FBR_CHUNK_LOADING) {
		async = 1;
	}

	fbr_hash_t hash = fbr_cstore_hash_chunk(cstore, file, chunk->id, chunk->offset);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, 0, NULL, 1);
	if (!entry) {
		// TODO we can just read the chunk and not write back if this is a problem
		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		fbr_rlog(FBR_LOG_CS_S3, "ERROR s3 loading state");
		return;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	struct fbr_cstore_path path;
	fbr_cstore_path_chunk(file, chunk->id, chunk->offset, &path);

	struct fbr_cstore_fetch_context fetch;
	struct chttp_context http;

	chttp_context_init(&http);
	fbr_cstore_fetch_init(&fetch, cstore, &http, FBR_CSTORE_FILE_CHUNK, &path, chunk->id,
		chunk->length, chunk->offset, 0, 0, FBR_CSTORE_ROUTE_CLUSTER);

	fbr_cstore_s3_send_get(&fetch);

	if (http.error || http.status != 200) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp: %d %d", http.error, http.status);
		_s3_chunk_read_error(fs, cstore, entry, file, chunk, &http);
		return;
	} else if (!http.chunked && (size_t)http.length != chunk->length) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp length");
		_s3_chunk_read_error(fs, cstore, entry, file, chunk, &http);
		return;
	}

	chunk->do_free = 1;
	chunk->data = malloc(chunk->length);
	assert(chunk->data);

	size_t bytes = 0;
	while (bytes < chunk->length) {
		bytes += chttp_body_read(&http, chunk->data + bytes, chunk->length - bytes);

		if (http.error || http.state >= CHTTP_STATE_IDLE) {
			break;
		}
	}

	if (http.error || bytes != chunk->length || http.state < CHTTP_STATE_IDLE) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp bytes");
		_s3_chunk_read_error(fs, cstore, entry, file, chunk, &http);
		return;
	}

	chttp_context_free(&http);

	fbr_rlog(FBR_LOG_CS_S3, "READ S3 %zu bytes", bytes);

	fbr_stat_add_count(&cstore->stats.rd_chunk_bytes, bytes);
	fbr_stat_add(&cstore->stats.fetch_chunks);

	if (!cstore->config.force_chunk_write) {
		struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash,
			FBR_CSTORE_ROUTE_CLUSTER, 0, 0);

		if (cstore->cluster.size && !fbr_cstore_servers_contains(cstore, backend)) {
			fbr_rlog(FBR_LOG_CS_WBUFFER, "READ S3 WRITE skipping local");

			fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);
			_s3_chunk_readwrite_error(fs, cstore, entry, file, chunk, 0);

			return;
		}
	}

	// Write back the chunk to the cstore

	int ret = fbr_cstore_set_size(cstore, entry, bytes);
	if (ret) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR READ S3 WRITE size");

		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);
		_s3_chunk_readwrite_error(fs, cstore, entry, file, chunk, 0);

		return;
	}

	if (async) {
		fbr_file_ref_inode(fs, file);
		fbr_file_LOCK(fs, file);
		fbr_chunk_take(chunk);
		fbr_file_UNLOCK(file);
	}

	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	fbr_rlog(FBR_LOG_CS_S3, "READ S3 WRITE chunk: %s", hashpath.value);

	ret = fbr_sys_mkdirs(hashpath.value);
	if (ret || fbr_sys_exists(hashpath.value)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR rwrite mkdir/exists (%d)", ret);
		_s3_chunk_readwrite_error(fs, cstore, entry, file, chunk, async);
		return;
	}

	int fd = open(hashpath.value, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR rwrite open()");
		_s3_chunk_readwrite_error(fs, cstore, entry, file, chunk, async);
		return;
	}

	bytes = fbr_sys_write(fd, chunk->data, chunk->length);
	assert_zero(close(fd));

	if (bytes != chunk->length) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR rwrite bytes");
		_s3_chunk_readwrite_error(fs, cstore, entry, file, chunk, async);
		return;
	}

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = chunk->id;
	metadata.size = bytes;
	metadata.offset = chunk->offset;
	metadata.type = FBR_CSTORE_FILE_CHUNK;

	fbr_cstore_path_chunk(file, chunk->id, chunk->offset, &path);
	fbr_strbcpy(metadata.path, path.value);

	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
	ret = fbr_cstore_metadata_write(&hashpath, &metadata);
	if (ret) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR rwrite metadata");
		_s3_chunk_readwrite_error(fs, cstore, entry, file, chunk, async);
		return;
	}

	if (async) {
		fbr_file_LOCK(fs, file);
		fbr_chunk_release(chunk);
		fbr_file_UNLOCK(file);
		fbr_inode_release(fs, &file);
	}

	fbr_rlog(FBR_LOG_CS_S3, "READ S3 WRITE done %zu bytes", bytes);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, &entry);
}

static void
_s3_writer_data_cb(struct chttp_context *http, void *arg)
{
	chttp_context_ok(http);
	assert(arg);

	struct fbr_writer *writer = arg;
	fbr_writer_ok(writer);
	assert_dev(writer->bytes);
	assert_dev(writer->output);
	assert_zero(writer->error);

	struct fbr_buffer *output = writer->output;
	while (output) {
		fbr_buffer_ok(output);

		if (output->buffer_pos) {
			chttp_body_send(http, output->buffer, output->buffer_pos);
			if (http->error) {
				return;
			}
		}

		output = output->next;
	}

	assert_zero(http->length);
}

void
fbr_cstore_s3_index_send(struct fbr_cstore *cstore, struct chttp_context *http,
    struct fbr_cstore_path *path, struct fbr_writer *writer, fbr_id_t id)
{
	struct fbr_cstore_fetch_context fetch;

	fbr_cstore_fetch_init(&fetch, cstore, http, FBR_CSTORE_FILE_INDEX, path, id,
		writer->bytes, 0, 0, writer->is_gzip, FBR_CSTORE_ROUTE_CLUSTER);

	fetch.data_callback = _s3_writer_data_cb;
	fetch.data_arg = writer;

	fbr_s3_send_put(&fetch);
}

int
fbr_cstore_s3_root_put(struct fbr_cstore *cstore, struct fbr_writer *root_json,
    struct fbr_cstore_path *root_path, fbr_id_t version, fbr_id_t existing,
    enum fbr_cstore_route route)
{
	fbr_cstore_ok(cstore);
	fbr_writer_ok(root_json);
	assert(root_json->bytes);
	fbr_cstore_path_ok(root_path);
	assert(version);
	assert(route);
	assert(fbr_cstore_backend_enabled(cstore));

	double timestamp = fbr_get_time();

	struct fbr_cstore_fetch_context fetch;
	struct chttp_context http;

	chttp_context_init(&http);
	fbr_cstore_fetch_init(&fetch, cstore, &http, FBR_CSTORE_FILE_ROOT, root_path, version,
		root_json->bytes, 0, existing, root_json->is_gzip, route);

	fetch.data_callback = _s3_writer_data_cb;
	fetch.data_arg = root_json;

	fbr_s3_send_put(&fetch);
	int error = fbr_cstore_s3_send_finish(cstore, NULL, &http, 0);
	if (error) {
		fbr_writer_free(root_json);
		return error;
	}

	if (cstore->config.async_write) {
		fbr_cstore_async_root_write(cstore, root_json, root_path, version, timestamp);
	} else {
		fbr_cstore_io_root_write(cstore, root_json, root_path, version, 0, 0, timestamp);
	}

	return 0;
}

fbr_id_t
fbr_cstore_s3_root_get(struct fbr_fs *fs, struct fbr_cstore *cstore,
    struct fbr_cstore_path *root_path, int route_s3)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_path_ok(root_path);

	enum fbr_cstore_route route = FBR_CSTORE_ROUTE_CLUSTER;
	if (route_s3) {
		route = FBR_CSTORE_ROUTE_S3;
	}

	struct fbr_cstore_fetch_context fetch;
	struct chttp_context http;

	double timestamp = fbr_get_time();

	chttp_context_init(&http);
	fbr_cstore_fetch_init(&fetch, cstore, &http, FBR_CSTORE_FILE_ROOT, root_path,
		0, 0, 0, 0, 0, route);

	fbr_cstore_s3_send_get(&fetch);

	if (http.error || http.status != 200) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR S3: %d %d", http.error, http.status);
		chttp_context_free(&http);
		return 0;
	}

	char root_json[FBR_ROOT_JSON_SIZE];
	size_t bytes = 0;

	while (bytes < sizeof(root_json)) {
		bytes += chttp_body_read(&http, root_json + bytes, sizeof(root_json) - bytes);
		assert_dev(bytes <= sizeof(root_json));

		if (http.error || http.state >= CHTTP_STATE_IDLE) {
			break;
		}
	}

	if (http.error || bytes == sizeof(root_json) || http.state < CHTTP_STATE_IDLE) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR S3 body");
		chttp_context_free(&http);
		return 0;
	}

	chttp_context_free(&http);

	fbr_id_t version = fbr_root_json_parse(root_json, bytes);
	if (!version) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR S3 json");
		return 0;
	}

	struct fbr_writer *json_writer = fbr_writer_alloc_dynamic(fs, FBR_ROOT_JSON_SIZE);
	fbr_writer_add(fs, json_writer, root_json, bytes);
	fbr_writer_flush(fs, json_writer);
	assert_zero(json_writer->error);

	if (cstore->config.async_write) {
		fbr_cstore_async_root_write(cstore, json_writer, root_path, version, timestamp);
	} else {
		fbr_cstore_io_root_write(cstore, json_writer, root_path, version, 0, 0, timestamp);
	}

	return version;
}
