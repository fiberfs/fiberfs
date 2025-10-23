/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>
#include <string.h>

#include "fiberfs.h"
#include "cstore/fbr_cstore_api.h"

struct fbr_cstore_backend *
fbr_cstore_backend_alloc(const char *host, int port, int tls)
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

	fbr_strcpy(backend->host, host_len + 1, host);

	fbr_cstore_backend_ok(backend);

	return backend;
}

void
fbr_cstore_backend_free(struct fbr_cstore_backend *backend)
{
	fbr_cstore_backend_ok(backend);

	fbr_zero(backend);
	free(backend);
}

void
fbr_cstore_s3_init(struct fbr_cstore *cstore, const char *host, int port, int tls,
    const char *prefix)
{
	fbr_cstore_ok(cstore);
	assert(host && *host);
	assert(port > 0 && port <= USHRT_MAX);

	struct fbr_cstore_s3 *s3 = &cstore->s3;

	fbr_zero(s3);
	s3->backend = fbr_cstore_backend_alloc(host, port, tls);

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
		fbr_cstore_backend_free(s3->backend);
	}
	if (s3->prefix) {
		free(s3->prefix);
	}

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

	struct fbr_cstore_backend *backend = fbr_cstore_backend_alloc(host, port, tls);
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
		fbr_cstore_backend_free(backend);
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

struct fbr_cstore_backend *
fbr_cstore_backend_get(struct fbr_cstore *cstore, fbr_hash_t hash, int retries, int skip_cdn)
{
	fbr_cstore_ok(cstore);
	assert_dev(cstore->s3.backend);

	assert_zero(cstore->cdn.size); // TODO
	(void)skip_cdn;

	// TODO implement rendezvous hash
	(void)hash;
	(void)retries;
	if (cstore->cluster.size) {
		assert(cstore->cluster.size == 1);  // TODO
		fbr_cstore_backend_ok(cstore->cluster.backends[0]);
		return cstore->cluster.backends[0];
	}

	fbr_cstore_backend_ok(cstore->s3.backend);
	return cstore->s3.backend;
}
