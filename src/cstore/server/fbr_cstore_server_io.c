/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fiberfs.h"
#include "chttp.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_api.h"
#include "utils/fbr_sys.h"

struct _cstore_entry_pair {
	struct fbr_cstore		*cstore;
	struct fbr_cstore_entry		*entry;
};

static void
_cstore_entry_sendfile(struct chttp_context *http, void *arg)
{
	chttp_context_ok(http);
	assert(arg);

	struct _cstore_entry_pair *pair = arg;

	struct fbr_cstore *cstore = pair->cstore;
	fbr_cstore_ok(cstore);

	struct fbr_cstore_entry *entry = pair->entry;
	fbr_cstore_entry_ok(entry);
	assert(entry->state == FBR_CSTORE_OK);
	assert(entry->bytes == (size_t)http->length);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, entry->hash, 0, &hashpath);

	int fd = open(hashpath.value, O_RDONLY);
	if (fd < 0) {
		chttp_error(http, CHTTP_ERR_NETWORK);
		return;
	}

	size_t bytes = fbr_cstore_s3_splice_out(cstore, &http->addr, fd, entry->bytes);

	assert_zero(close(fd));

	if (bytes != entry->bytes) {
		fbr_rlog(FBR_LOG_CS_S3, "URL_WRITE ERROR splice_out");
		chttp_error(http, CHTTP_ERR_NETWORK);
		return;
	}

	http->length -= bytes;
	assert_zero(http->length);
}

static void
_cstore_root_proxy(struct fbr_cstore *cstore, struct chttp_context *http, const char *url,
    const char *etag_match)
{
	assert_dev(cstore);
	assert_dev(http);
	assert_dev(url);

	char root_buffer[FBR_ROOT_JSON_SIZE];
	size_t bytes = 0;

	while (bytes < sizeof(root_buffer)) {
		bytes += chttp_body_read(http, root_buffer + bytes, sizeof(root_buffer) - bytes);
		assert_dev(bytes <= sizeof(root_buffer));

		if (http->error || http->state >= CHTTP_STATE_IDLE) {
			break;
		}
	}

	if (http->error || bytes == sizeof(root_buffer) || http->state < CHTTP_STATE_IDLE) {
		fbr_rlog(FBR_LOG_CS_WORKER, "ERROR S3 root_body");
		chttp_context_free(http);
		return;
	}

	struct fbr_writer *root_json = fbr_writer_alloc_dynamic(NULL, FBR_ROOT_JSON_SIZE);
	fbr_writer_add(NULL, root_json, root_buffer, bytes);
	fbr_writer_flush(NULL, root_json);
	assert_zero_dev(root_json->error);

	struct fbr_cstore_path root_path;
	fbr_cstore_path_url(cstore, url, &root_path);

	struct fbr_etag etag;
	fbr_cstore_etag_init(&etag, NULL);

	int error = fbr_cstore_s3_root_put(cstore, root_json, &root_path, &etag, etag_match,
		FBR_CSTORE_ROUTE_S3);
	if (error) {
		assert_zero_dev(fbr_cstore_http_success(error));
		fbr_cstore_http_respond(cstore, http, error, "Error");
		return;
	}

	assert(etag.length);

	fbr_cstore_http_resp_etag(cstore, http, 200, "OK", etag.value);
}

void
fbr_cstore_url_write(struct fbr_cstore_worker *worker, struct chttp_context *http)
{
	fbr_cstore_worker_ok(worker);
	chttp_context_ok(http);
	assert(http->state == CHTTP_STATE_BODY);
	assert_zero(http->chunked);
	chttp_addr_connected(&http->addr);

	struct fbr_cstore *cstore = worker->cstore;
	fbr_cstore_ok(cstore);

	if (http->chunked) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR chunked");
		fbr_cstore_http_respond(cstore, http, 500, "Error");
		return;
	}

	size_t length = http->length;
	assert(length);
	size_t cstore_len = length;

	const char *url_encoded = chttp_header_get_url(http);
	assert(url_encoded);
	size_t url_encoded_len = strlen(url_encoded);
	if (url_encoded_len >= FBR_URL_MAX) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url_encoded_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_urldecode(url_encoded, url_encoded_len, url, sizeof(url));
	if (!url_len) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}
	assert(url[0] == '/');

	int ret = fbr_cstore_s3_validate(cstore, http);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR auth");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	const char *host = chttp_header_get(http, "Host");
	if (!host) {
		host = "";
	}
	size_t host_len = strlen(host);

	int unique = 0;
	const char *if_none_match = chttp_header_get(http, "If-None-Match");
	if (if_none_match) {
		if (!strcmp(if_none_match, "*")) {
			unique = 1;
		} else {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR if-none-match");
			fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
			return;
		}
	}

	const char *etag_match = chttp_header_get(http, "If-Match");

	enum fbr_cstore_file_type file_type = fbr_cstore_s3_url_parse(url, url_len);
	if (file_type == FBR_CSTORE_FILE_NONE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	switch (file_type) {
		case FBR_CSTORE_FILE_CHUNK:
		case FBR_CSTORE_FILE_INDEX:
			if (!unique || etag_match) {
				fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
					"URL_WRITE ERROR need unique");
				fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
				return;
			}
			break;
		case FBR_CSTORE_FILE_ROOT:
			if ((unique && etag_match) || (!unique && !etag_match)) {
				fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
					"URL_WRITE ERROR root missing conditions");
				fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
				return;
			}
			cstore_len = FBR_CSTORE_ROOT_SIZE;
			break;
		default:
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url type");
			fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
			return;
	}

	int backend = fbr_cstore_backend_enabled(cstore);

	// root files put first then write
	if (backend && file_type == FBR_CSTORE_FILE_ROOT) {
		_cstore_root_proxy(cstore, http, url_encoded, etag_match);
		return;
	}

	fbr_hash_t hash = fbr_cstore_hash_url(host, host_len, url, url_len);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE %s %s unique: %d match: [%s]",
		fbr_cstore_type_name(file_type), hashpath.value, unique,
		etag_match ? etag_match : "none");

	struct fbr_cstore_entry *entry = NULL;
	if (unique) {
		entry = fbr_cstore_io_get_loading(cstore, hash, cstore_len, &hashpath);
		if (!entry) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR loading state");

			if (backend) {
				fbr_cstore_http_respond(cstore, http, 500, "Error");
			} else {
				fbr_cstore_http_respond(cstore, http, 412, "Exists");
			}

			return;
		}
	} else {
		assert_dev(etag_match);
		assert_dev(file_type == FBR_CSTORE_FILE_ROOT);

		entry = fbr_cstore_get(cstore, hash);
		if (entry) {
			fbr_cstore_reset_loading(entry);
		} else {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
				"URL_WRITE ERROR loading state 2");
			fbr_cstore_http_respond(cstore, http, 412, "Missing");
			return;
		}
	}

	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	if (etag_match) {
		assert_dev(file_type == FBR_CSTORE_FILE_ROOT);
		assert_zero_dev(backend);

		struct fbr_cstore_metadata metadata;
		fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
		int ret = fbr_cstore_metadata_read(&hashpath, &metadata);
		if (ret) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR metadata");
			fbr_cstore_set_error(entry);
			fbr_cstore_remove(cstore, &entry);
			fbr_cstore_http_respond(cstore, http, 500, "Error");
			return;
		}

		if (strcmp(metadata.etag.value, etag_match)) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
				"URL_WRITE ERROR bad etag want: %s got: %s",
				etag_match, metadata.etag.value);
			fbr_cstore_set_ok(entry);
			fbr_cstore_release(cstore, &entry);
			fbr_cstore_http_respond(cstore, http, 412, "Mismatch");
			return;
		}

		fbr_cstore_hashpath(cstore, hash, 0, &hashpath);
	}

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE conditions passed");

	if (file_type == FBR_CSTORE_FILE_ROOT && !fbr_sys_exists(hashpath.value)) {
		fbr_stat_add(&cstore->stats.wr_roots);
	}

	int fd = open(hashpath.value, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		fbr_cstore_http_respond(cstore, http, 500, "Error");
		return;
	}

	size_t bytes = fbr_cstore_s3_splice_in(cstore, http, fd, length);

	assert_zero(close(fd));

	if (bytes != length) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR splice_in (%zu)",
			bytes);

		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);

		if (!http->error) {
			chttp_error(http, CHTTP_ERR_NETWORK);
		}
		assert_dev(http->addr.state != CHTTP_ADDR_CONNECTED);

		return;
	} else {
		assert_dev(http->state >= CHTTP_STATE_IDLE);
		assert_zero_dev(http->length);
	}

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE wrote %zu bytes", bytes);

	struct fbr_cstore_path file_path;
	fbr_cstore_path_url(cstore, url_encoded, &file_path);

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.size = length;
	metadata.type = file_type;
	metadata.gzipped = http->gzip;
	fbr_strbcpy(metadata.path, file_path.value);

	char *etag_hdr = NULL;
	if (file_type == FBR_CSTORE_FILE_ROOT) {
		assert_zero_dev(backend);

		fbr_cstore_gen_etag(&metadata.etag);
		etag_hdr = metadata.etag.value;

		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE new Etag [%s]", etag_hdr);
	}

	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
	ret = fbr_cstore_metadata_write(&hashpath, &metadata);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		fbr_cstore_http_respond(cstore, http, 500, "Error");
		return;
	}

	fbr_cstore_set_ok(entry);

	if (backend) {
		assert(file_type != FBR_CSTORE_FILE_ROOT);

		struct fbr_cstore_fetch_context fetch;
		struct chttp_context http_backend;

		chttp_context_init(&http_backend);
		fbr_cstore_fetch_init(&fetch, cstore, &http_backend, file_type, &file_path, NULL,
			NULL, length, metadata.gzipped, FBR_CSTORE_ROUTE_CDN);

		struct _cstore_entry_pair pair;
		pair.cstore = cstore;
		pair.entry = entry;

		fetch.data_callback = _cstore_entry_sendfile;
		fetch.data_arg = &pair;

		fbr_s3_send_put(&fetch);

		if (http_backend.error || !fbr_cstore_http_success(http_backend.status)) {
			fbr_cstore_release(cstore, &entry);
			chttp_context_free(&http_backend);
			fbr_cstore_http_respond(cstore, http, http_backend.status, "Error");
			return;
		}

		// TODO return the http_backend response better

		chttp_context_free(&http_backend);
	}

	fbr_cstore_release(cstore, &entry);
	assert_zero_dev(entry);

	fbr_cstore_http_resp_etag(cstore, http, 200, "OK", etag_hdr);

	switch (file_type) {
		case FBR_CSTORE_FILE_CHUNK:
			fbr_stat_add_count(&cstore->stats.wr_chunk_bytes, bytes);
			fbr_stat_add(&cstore->stats.wr_chunks);
			break;
		case FBR_CSTORE_FILE_INDEX:
			fbr_stat_add_count(&cstore->stats.wr_index_bytes, bytes);
			fbr_stat_add(&cstore->stats.wr_indexes);
			break;
		case FBR_CSTORE_FILE_ROOT:
			fbr_stat_add_count(&cstore->stats.wr_root_bytes, bytes);
			fbr_stat_add(&cstore->stats.wr_root_updates);
			break;
		default:
			break;
	}
}

static void
_cstore_url_entry_release(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry,
    enum fbr_cstore_file_type file_type, int error)
{
	assert_dev(cstore);
	assert_dev(entry);
	assert(file_type >= FBR_CSTORE_FILE_CHUNK && file_type <= FBR_CSTORE_FILE_ROOT);

	if (file_type == FBR_CSTORE_FILE_ROOT) {
		assert(entry->state == FBR_CSTORE_LOADING);

		if (error) {
			fbr_cstore_set_error(entry);
		} else {
			fbr_cstore_set_ok(entry);
		}
	}

	if (error) {
		fbr_cstore_remove(cstore, &entry);
	} else {
		fbr_cstore_release(cstore, &entry);
	}

	assert_zero_dev(entry);
}

void
fbr_cstore_url_read(struct fbr_cstore_worker *worker, struct chttp_context *http)
{
	fbr_cstore_worker_ok(worker);
	chttp_context_ok(http);
	assert(http->state == CHTTP_STATE_IDLE);
	chttp_addr_connected(&http->addr);

	struct fbr_cstore *cstore = worker->cstore;
	fbr_cstore_ok(cstore);

	const char *url_encoded = chttp_header_get_url(http);
	assert(url_encoded);
	size_t url_encoded_len = strlen(url_encoded);
	if (url_encoded_len >= FBR_URL_MAX) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR url_encoded_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_urldecode(url_encoded, url_encoded_len, url, sizeof(url));
	if (!url_len) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR url_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}
	assert(url[0] == '/');

	int ret = fbr_cstore_s3_validate(cstore, http);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR auth");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	const char *host = chttp_header_get(http, "Host");
	assert(host);
	size_t host_len = strlen(host);

	enum fbr_cstore_file_type file_type = fbr_cstore_s3_url_parse(url, url_len);
	if (file_type == FBR_CSTORE_FILE_NONE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR url");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	int backend = fbr_cstore_backend_enabled(cstore);

	fbr_hash_t hash = fbr_cstore_hash_url(host, host_len, url, url_len);
	struct fbr_cstore_hashpath hashpath;
	struct fbr_cstore_metadata metadata;
	struct fbr_cstore_entry *entry;
	struct fbr_etag server_etag;
	int fd;
	size_t size;
	int retry = 0;
	int skip_ttl = 0;
	int http_error = 0;
	int was_304 = 0;

	struct fbr_cstore_entry_ref entry_ref;
	fbr_cstore_entry_ref_init(&entry_ref);
	entry_ref.want_ref = 1;

	fbr_cstore_etag_init(&server_etag, NULL);

	while (1) {
		fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ %s %s (retry: %d)",
			fbr_cstore_type_name(file_type), hashpath.value, retry);

		if (retry == 1 && file_type == FBR_CSTORE_FILE_ROOT) {
			if (!backend) {
				assert_zero(fbr_cstore_entry_has_ref(&entry_ref));
				fbr_cstore_http_respond(cstore, http, 404, "Not found");
				return;
			}

			struct fbr_cstore_path file_path;
			fbr_cstore_path_url(cstore, url_encoded, &file_path);

			fbr_cstore_s3_root_get(NULL, cstore, &file_path, &server_etag, 1,
				&entry_ref, &http_error, 1);

			skip_ttl = 1;
		} else if (retry == 1) {
			assert_zero(fbr_cstore_entry_has_ref(&entry_ref));

			if (!backend) {
				fbr_cstore_http_respond(cstore, http, 404, "Not found");
				return;
			}

			struct fbr_cstore_path file_path;
			fbr_cstore_path_url(cstore, url_encoded, &file_path);

			struct fbr_cstore_fetch_context fetch;
			struct chttp_context http;

			chttp_context_init(&http);
			fbr_cstore_fetch_init(&fetch, cstore, &http, file_type,
				&file_path, NULL, NULL, 0, 0, FBR_CSTORE_ROUTE_CDN);

			http_error = fbr_cstore_s3_get_write(&fetch, hash, &entry_ref);
			assert_dev(http.state == CHTTP_STATE_NONE);
		} else if (retry > 1) {
			assert_zero(fbr_cstore_entry_has_ref(&entry_ref));

			if (http_error && !fbr_cstore_http_success(http_error)) {
				fbr_cstore_http_respond(cstore, http, http_error, "Error");
			} else {
				fbr_cstore_http_respond(cstore, http, 500, "Error");
			}

			return;
		}

		retry++;

		if (http_error == 304) {
			assert(file_type == FBR_CSTORE_FILE_ROOT);
			assert(fbr_cstore_entry_has_ref(&entry_ref));
			was_304 = 1;
		}

		if (file_type == FBR_CSTORE_FILE_ROOT) {
			entry = fbr_cstore_entry_ref_take(&entry_ref);
			if (!entry) {
				entry = fbr_cstore_get(cstore, hash);
				if (!entry) {
					fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
						"URL_READ NO entry");
					continue;
				}

				fbr_cstore_reset_loading(entry);
			}

			assert(entry->state == FBR_CSTORE_LOADING);
		} else {
			entry = fbr_cstore_entry_ref_take(&entry_ref);
			if (!entry) {
				entry = fbr_cstore_io_get_ok(cstore, hash);
				if (!entry) {
					fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
						"URL_READ NO ok state");
					continue;
				}
			}

			assert(entry->state == FBR_CSTORE_OK);
		}

		fbr_cstore_entry_ok(entry);
		assert_zero(fbr_cstore_entry_has_ref(&entry_ref));

		http_error = 0;

		fd = open(hashpath.value, O_RDONLY);
		if (fd < 0) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR open()");
			_cstore_url_entry_release(cstore, entry, file_type, 1);
			continue;
		}

		struct stat st;
		int ret = fstat(fd, &st);
		if (ret) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR stat()");
			_cstore_url_entry_release(cstore, entry, file_type, 1);
			assert_zero(close(fd));
			continue;
		}

		size = (size_t)st.st_size;

		fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
		ret = fbr_cstore_metadata_read(&hashpath, &metadata);

		if (ret || metadata.size != size || metadata.type != file_type) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR metadata()");
			_cstore_url_entry_release(cstore, entry, file_type, 1);
			assert_zero(close(fd));
			continue;
		}

		if (backend && file_type == FBR_CSTORE_FILE_ROOT && !skip_ttl) {
			fbr_cstore_etag_init(&server_etag, metadata.etag.value);

			double now = fbr_get_time();
			double root_time = metadata.timestamp +
				(cstore->config.root_ttl_sec ? cstore->config.root_ttl_sec :
					FBR_CSTORE_ROOT_TTL_MIN);

			if (root_time < now) {
				fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
					"URL_READ ERROR root expired");

				fbr_cstore_entry_ref_set(cstore, &entry_ref, entry, &metadata, 0);
				assert_dev(entry_ref.has_ref);
				assert_dev(entry_ref.want_ref);

				fbr_cstore_release(cstore, &entry);
				assert_zero(close(fd));

				continue;
			}
		}

		break;
	}

	assert_zero(fbr_cstore_entry_has_ref(&entry_ref));

	// TODO do we care about accept-encoding gzip?

	if (was_304) {
		assert_dev(file_type == FBR_CSTORE_FILE_ROOT);

		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ROOT TOUCH %s",
			hashpath.value);

		double now = fbr_get_time();
		metadata.timestamp = now;

		int ret = fbr_cstore_metadata_write(&hashpath, &metadata);
		if (ret) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR write metadata");

			_cstore_url_entry_release(cstore, entry, file_type, 1);
			assert_zero(close(fd));

			fbr_cstore_http_respond(cstore, http, 500, "Error");

			return;
		}
	}

	const char *if_none_match = chttp_header_get(http, "If-None-Match");
	if (if_none_match && !strcmp(if_none_match, metadata.etag.value)) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ 304 matched");

		_cstore_url_entry_release(cstore, entry, file_type, 0);
		assert_zero(close(fd));

		fbr_cstore_http_respond(cstore, http, 304, "Not Modified");

		return;
	}

	const char *etag = NULL;
	if (file_type == FBR_CSTORE_FILE_ROOT) {
		assert(metadata.etag.length);
		etag = metadata.etag.value;
	}

	char fiber_id[32];
	fbr_cstore_request_id(fiber_id, sizeof(fiber_id));

	char buffer[1024];
	size_t header_len = fbr_bprintf(buffer,
		"HTTP/1.1 200 OK\r\n"
		"Server: fiberfs cstore %s\r\n"
		"%s"
		"%s"
		"%s%s%s"
		"FiberFS-ID: %s\r\n"
		"Content-Length: %zu\r\n\r\n",
			FIBERFS_VERSION,
			metadata.gzipped ? "Content-Encoding: gzip\r\n" : "",
			cstore->epool.timeout_sec ? "" : "Connection: close\r\n",
			etag ? "ETag: " : "", etag ? etag : "", etag ? "\r\n" : "",
			fiber_id, size);

	chttp_tcp_send(&http->addr, buffer, header_len);
	chttp_tcp_error_check(http);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "sent response 200 OK");
	fbr_stat_add(&cstore->stats.http_200);

	if (http->error) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR send() headers");
		_cstore_url_entry_release(cstore, entry, file_type, 0);
		assert_zero(close(fd));
		return;
	}

	size_t bytes = fbr_cstore_s3_splice_out(cstore, &http->addr, fd, size);

	assert_zero(close(fd));

	if (bytes != size) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR splice_out");
		_cstore_url_entry_release(cstore, entry, file_type, 0);
		chttp_error(http, CHTTP_ERR_NETWORK);
		return;
	}

	_cstore_url_entry_release(cstore, entry, file_type, 0);

	if (file_type == FBR_CSTORE_FILE_CHUNK) {
		fbr_stat_add_count(&cstore->stats.rd_chunk_bytes, bytes);
	}
}

void
fbr_cstore_url_delete(struct fbr_cstore_worker *worker, struct chttp_context *http)
{
	fbr_cstore_worker_ok(worker);
	chttp_context_ok(http);
	assert(http->state == CHTTP_STATE_IDLE);
	chttp_addr_connected(&http->addr);

	struct fbr_cstore *cstore = worker->cstore;
	fbr_cstore_ok(cstore);

	const char *url_encoded = chttp_header_get_url(http);
	assert(url_encoded);
	size_t url_encoded_len = strlen(url_encoded);
	if (url_encoded_len >= FBR_URL_MAX) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR url_encoded_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_urldecode(url_encoded, url_encoded_len, url, sizeof(url));
	if (!url_len) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR url_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}
	assert(url[0] == '/');

	int ret = fbr_cstore_s3_validate(cstore, http);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR auth");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	const char *host = chttp_header_get(http, "Host");
	assert(host);
	size_t host_len = strlen(host);

	const char *etag_match = chttp_header_get(http, "If-Match");

	enum fbr_cstore_file_type file_type = fbr_cstore_s3_url_parse(url, url_len);
	if (file_type == FBR_CSTORE_FILE_NONE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR url");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	} else if (file_type == FBR_CSTORE_FILE_ROOT && !etag_match) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR no etag match");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	int backend = fbr_cstore_backend_enabled(cstore);

	if (!cstore->config.delete_cache && backend) {
		struct fbr_cstore_url url_enc;
		fbr_cstore_s3_url_init(&url_enc, url_encoded, url_encoded_len);

		int error = fbr_cstore_s3_send_delete(cstore, &url_enc, etag_match,
			FBR_CSTORE_ROUTE_CDN);
		if (error) {
			assert_zero_dev(fbr_cstore_http_success(error));
			fbr_cstore_http_respond(cstore, http, error, "Error");
		} else {
			fbr_cstore_http_respond(cstore, http, 200, "OK");
		}

		return;
	}

	fbr_hash_t hash = fbr_cstore_hash_url(host, host_len, url, url_len);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE %s",
		fbr_cstore_type_name(file_type));

	int error = 0;

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (entry) {
		fbr_cstore_entry_ok(entry);

		if (!backend) {
			struct fbr_cstore_hashpath hashpath;
			fbr_cstore_hashpath(cstore, hash, 1, &hashpath);

			struct fbr_cstore_metadata metadata;
			int ret = fbr_cstore_metadata_read(&hashpath, &metadata);
			if (ret) {
				fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
					"URL_DELETE ERROR metadata");
				fbr_cstore_remove(cstore, &entry);
				fbr_cstore_http_respond(cstore, http, 500, "Error");
				return;
			} else if (etag_match && strcmp(metadata.etag.value, etag_match)) {
				fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR etag");
				fbr_cstore_release(cstore, &entry);
				fbr_cstore_http_respond(cstore, http, 412, "Mismatch");
				return;
			}
		}

		fbr_cstore_remove(cstore, &entry);
		assert_zero_dev(entry);

		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE success");
	} else {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE NO ok state");
		error = 404;
	}

	if (!error) {
		switch (file_type) {
			case FBR_CSTORE_FILE_CHUNK:
				fbr_stat_sub(&cstore->stats.wr_chunks);
				break;
			case FBR_CSTORE_FILE_INDEX:
				fbr_stat_sub(&cstore->stats.wr_indexes);
				break;
			case FBR_CSTORE_FILE_ROOT:
				fbr_stat_sub(&cstore->stats.wr_roots);
				break;
			default:
				break;
		}
	}

	if (backend) {
		struct fbr_cstore_url url_enc;
		fbr_cstore_s3_url_init(&url_enc, url_encoded, url_encoded_len);

		error = fbr_cstore_s3_send_delete(cstore, &url_enc, etag_match,
			FBR_CSTORE_ROUTE_CDN);
	}

	if (error) {
		assert_zero_dev(fbr_cstore_http_success(error));
		fbr_cstore_http_respond(cstore, http, error, "Error");
	} else {
		fbr_cstore_http_respond(cstore, http, 200, "OK");
	}
}
