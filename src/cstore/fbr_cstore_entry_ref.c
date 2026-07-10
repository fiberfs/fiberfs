/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore_api.h"

void
fbr_cstore_entry_ref_init(struct fbr_cstore_entry_ref *entry_ref)
{
	assert(entry_ref);

	entry_ref->entry = NULL;
	entry_ref->has_ref = 0;
	entry_ref->want_ref = 0;
}

int
fbr_cstore_entry_has_ref(struct fbr_cstore_entry_ref *entry_ref)
{
	if (!entry_ref) {
		return 0;
	} else if (!entry_ref->has_ref) {
		assert_zero(entry_ref->entry);
		return 0;
	}

	fbr_cstore_entry_ok(entry_ref->entry);

	return 1;
}

int
fbr_cstore_entry_want_ref(struct fbr_cstore_entry_ref *entry_ref)
{
	if (!entry_ref) {
		return 0;
	} else if (!entry_ref->want_ref) {
		return 0;
	}

	assert_zero(entry_ref->entry);

	return 1;
}

struct fbr_cstore_entry *
fbr_cstore_entry_ref_take(struct fbr_cstore_entry_ref *entry_ref)
{
	if (!fbr_cstore_entry_has_ref(entry_ref)) {
		return NULL;
	}

	struct fbr_cstore_entry *entry = entry_ref->entry;
	assert_dev(entry);

	entry_ref->entry = NULL;
	entry_ref->has_ref = 0;

	return entry;
}

void
fbr_cstore_entry_ref_set(struct fbr_cstore *cstore, struct fbr_cstore_entry_ref *entry_ref,
    struct fbr_cstore_entry *entry, struct fbr_cstore_metadata *metadata, fbr_id_t version)
{
	fbr_cstore_ok(cstore);
	assert(entry_ref);
	assert_zero(fbr_cstore_entry_has_ref(entry_ref));
	fbr_cstore_entry_ok(entry);
	assert(metadata);

	entry_ref->entry = fbr_cstore_ref(cstore, entry);
	entry_ref->version = version;
	entry_ref->has_ref = 1;

	memcpy(&entry_ref->metadata, metadata, sizeof(*metadata));
}
