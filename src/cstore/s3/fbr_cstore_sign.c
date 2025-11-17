/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "chttp.h"
#include "cstore/fbr_cstore_api.h"

int
fbr_cstore_s3_sign(struct fbr_cstore *cstore, struct chttp_context *http)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(http);

	struct chttp_dpage *dpage = http->dpage;
	chttp_dpage_ok(dpage);

	size_t method_len = 0;
	size_t url_len = 0;

	for (size_t i = 0; i < dpage->length; i++) {
		assert(dpage->data[i] != '\r');
		if (dpage->data[i] == ' ') {
			if (!method_len) {
				assert(i);
				method_len = i;
			} else {
				assert(i > method_len);
				url_len = i - method_len - 1;
				break;
			}
		}
	}
	assert(method_len);
	assert(url_len);

	const char *method = (char*)dpage->data;
	const char *url = (char*)dpage->data + method_len + 1;

	fbr_rlog(FBR_LOG_CS_S3, "TODO_SIGN '%.*s':%zu '%.*s':%zu",
		(int)method_len, method, method_len, (int)url_len, url, url_len);

	return 0;
}
