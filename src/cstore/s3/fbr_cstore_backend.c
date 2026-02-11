/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdlib.h>
#include <string.h>

#include "fiberfs.h"
#include "cstore/fbr_cstore_api.h"

#define _BACKEND_HASH_STACK_SIZE	16

struct _backend_hash {
	struct fbr_cstore_backend	*backend;
	fbr_hash_t			hash;
};

static struct fbr_cstore_backend *
_backend_alloc(const char *host, int port, int tls)
{
	assert(host);

	size_t host_len = strlen(host);
	assert(host_len);

	struct fbr_cstore_backend *backend = malloc(sizeof(*backend) + host_len + 1);
	assert(backend);

	fbr_zero(backend);
	backend->magic = FBR_CSTORE_BACKEND_MAGIC;
	backend->port = port;
	backend->host = (char*)(backend + 1);
	backend->host_len = host_len;
	backend->tls = tls ? 1 : 0;
	backend->hash = fbr_hash(host, host_len);

	fbr_strcpy(backend->host, host_len + 1, host);

	fbr_cstore_backend_ok(backend);

	return backend;
}

static void
_backend_free(struct fbr_cstore_backend *backend)
{
	fbr_cstore_backend_ok(backend);

	fbr_zero(backend);
	free(backend);
}

void
fbr_cstore_s3_init(struct fbr_cstore *cstore, const char *host, int port, int tls,
    const char *prefix, const char *region, const char *access_key, const char *secret_key)
{
	fbr_cstore_ok(cstore);
	assert(region);
	assert(access_key);
	assert(secret_key);

	struct fbr_cstore_s3 *s3 = &cstore->s3;
	fbr_zero(s3);

	if (host) {
		assert(host && *host);
		assert(port > 0 && port <= USHRT_MAX);
		s3->backend = _backend_alloc(host, port, tls);
		assert_dev(s3->backend);
	}

	s3->region = strdup(region);
	assert(s3->region);
	s3->region_len = strlen(s3->region);
	assert(s3->region_len);

	s3->access_key = strdup(access_key);
	assert(s3->access_key);
	s3->access_key_len = strlen(s3->access_key);
	assert(s3->access_key_len);

	s3->secret_key = strdup(secret_key);
	assert(s3->secret_key);
	s3->secret_key_len = strlen(s3->secret_key);
	assert(s3->secret_key_len);

	if (prefix) {
		s3->prefix_len = strlen(prefix);
		if (s3->prefix_len >= 2 && prefix[0] == '/' && prefix[1] != '/') {
			s3->prefix = strdup(prefix);
			while (s3->prefix[s3->prefix_len - 1] == '/') {
				s3->prefix[s3->prefix_len - 1] = '\0';
				s3->prefix_len --;
				assert(s3->prefix_len);
			}
		} else {
			s3->prefix_len = 0;
		}
	}
}

void
fbr_cstore_s3_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_s3 *s3 = &cstore->s3;

	if (s3->backend) {
		_backend_free(s3->backend);
	}

	if (s3->prefix) {
		free(s3->prefix);
	}

	free(s3->region);
	free(s3->access_key);
	free(s3->secret_key);

	fbr_zero(s3);
}

void
fbr_cstore_cluster_init(struct fbr_cstore_cluster *cluster)
{
	assert(cluster);

	assert_zero_dev(cluster->backends);
	assert_zero_dev(cluster->size);
}

void
fbr_cstore_cluster_add(struct fbr_cstore_cluster *cluster, const char *host, int port, int tls)
{
	assert(cluster);
	assert(host);
	assert(port > 0 && port <= USHRT_MAX);

	struct fbr_cstore_backend *backend = _backend_alloc(host, port, tls);
	cluster->size++;
	assert(cluster->size < 100000);
	cluster->backends = realloc(cluster->backends, sizeof(backend) * cluster->size);
	assert(cluster->backends);

	cluster->backends[cluster->size - 1] = backend;
}

void
fbr_cstore_cluster_free(struct fbr_cstore_cluster *cluster)
{
	assert(cluster);

	for (size_t i = 0; i < cluster->size; i++) {
		struct fbr_cstore_backend *backend = cluster->backends[i];
		_backend_free(backend);
		cluster->backends[i] = NULL;
	}

	free(cluster->backends);
	fbr_zero(cluster);
}

int
fbr_cstore_backend_enabled(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	if (cstore->cluster.size) {
		assert_dev(cstore->s3.backend);
		return 1;
	} else if (cstore->cdn.size) {
		assert_dev(cstore->s3.backend);
		return 1;
	} else if (cstore->s3.backend) {
		return 1;
	}

	return 0;
}

static int
_backend_hash_cmp(const void *arg1, const void *arg2)
{
	assert(arg1);
	assert(arg2);

	const struct _backend_hash *hash1 = arg1;
	fbr_cstore_backend_ok(hash1->backend);
	const struct _backend_hash *hash2 = arg2;
	fbr_cstore_backend_ok(hash2->backend);

	if (!hash1->backend->offline && hash2->backend->offline) {
		return 1;
	} else if (hash1->backend->offline && !hash2->backend->offline) {
		return -1;
	}

	if (hash1->hash > hash2->hash) {
		return 1;
	} else if (hash1->hash < hash2->hash) {
		return -1;
	}

	return 0;
}

static struct fbr_cstore_backend *
_backend_rv_hash(struct fbr_cstore_cluster *cluster, fbr_hash_t hash, unsigned int retries)
{
	assert_dev(cluster);
	assert_dev(cluster->size);

	if (cluster->size == 1) {
		return cluster->backends[0];
	}

	struct _backend_hash *hashes = NULL;
	struct _backend_hash _hash_stack[_BACKEND_HASH_STACK_SIZE];
	int do_free = 0;

	if (cluster->size <= _BACKEND_HASH_STACK_SIZE) {
		hashes = _hash_stack;
	} else {
		struct fbr_cstore_worker *worker = fbr_cstore_worker_get();
		if (worker) {
			hashes = fbr_workspace_alloc(worker->workspace,
				sizeof(*hashes) * cluster->size);
		}

		if (!hashes) {
			hashes = malloc(sizeof(*hashes) * cluster->size);
			assert(hashes);

			do_free = 1;
		}
	}

	for (size_t i = 0; i < cluster->size; i++) {
		hashes[i].backend = cluster->backends[i];

		char hash_buf[sizeof(fbr_hash_t) * 2];
		static_ASSERT(sizeof(hash) == sizeof(cluster->backends[i]->hash));
		memcpy(hash_buf, &hash, sizeof(hash));
		memcpy(hash_buf + sizeof(hash), &cluster->backends[i]->hash, sizeof(hash));
		hashes[i].hash = fbr_hash(hash_buf, sizeof(hash_buf));
	}

	qsort(hashes, cluster->size, sizeof(*hashes), _backend_hash_cmp);

	struct fbr_cstore_backend *backend = hashes[0].backend;

	if (retries) {
		if (retries >= cluster->size) {
			retries = cluster->size - 1;
		}

		assert_dev(retries <= cluster->size);

		backend = hashes[retries].backend;
	}

	if (do_free) {
		free(hashes);
	}

	fbr_cstore_backend_ok(backend);

	return backend;
}

struct fbr_cstore_backend *
fbr_cstore_backend_get(struct fbr_cstore *cstore, fbr_hash_t hash, enum fbr_cstore_route route,
    int retries, int cdn_ok)
{
	fbr_cstore_ok(cstore);
	assert_dev(cstore->s3.backend);
	assert(route && route <= FBR_CSTORE_ROUTE_S3);
	assert(retries >= 0);

	if (route == FBR_CSTORE_ROUTE_CLUSTER && cstore->cluster.size) {
		return _backend_rv_hash(&cstore->cluster, hash, retries);
	} else if (route <= FBR_CSTORE_ROUTE_CDN && cdn_ok && cstore->cdn.size) {
		return _backend_rv_hash(&cstore->cdn, hash, retries);
	}

	fbr_cstore_backend_ok(cstore->s3.backend);

	return cstore->s3.backend;
}
