/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "log/fbr_log.h"
#include "test/fbr_test.h"

extern struct fbr_log *_LOG;

void
_test_log_debug(struct fbr_log *log, struct fbr_log_header *header)
{
	fbr_log_ok(log);

	fbr_test_logs("LOG->name: '%s'", log->shm_name);
	fbr_test_logs("LOG->shm_fd: %d", log->shm_fd);
	fbr_test_logs("LOG->mmap_size: %zu", log->mmap_size);
	fbr_test_logs("LOG->mmap_ptr: %p", log->mmap_ptr);
	fbr_test_logs("LOG->time_created: %lf", log->time_created);
	fbr_test_logs("LOG->block_size: %zu", log->block_size);
	fbr_test_logs("LOG->block_count: %zu", log->block_count);
	fbr_test_logs("LOG->blocks: %p", log->blocks);

	if (!header) {
		return;
	}

	fbr_log_header_ok(header);

	fbr_test_logs("HEADER->time_created: %lf", header->time_created);
	fbr_test_logs("HEADER->size: %zu", header->size);
	fbr_test_logs("HEADER->entry_count: %zu", header->entry_count);

	size_t entry_size = header->entry_count * sizeof(struct fbr_log_entry);
	size_t blocks_size = log->block_size * log->block_count;
	assert(header->entry_count >= log->block_count);
	size_t entry_waste = header->entry_count - log->block_count;
	assert(header->size >= entry_size + blocks_size);
	size_t byte_waste = header->size - (entry_size + blocks_size);

	fbr_test_logs("LOG entry size: %zu", entry_size);
	fbr_test_logs("LOG blocks size: %zu", blocks_size);
	fbr_test_logs("LOG entry waste: %zu", entry_waste);
	fbr_test_logs("LOG byte waste: %zu", byte_waste);
}

void
fbr_cmd_test_log_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_log_init_global("/test/123");
	fbr_log_ok(_LOG);

	struct fbr_log_header *header = fbr_log_header(_LOG, _LOG->mmap_ptr, _LOG->mmap_size);
	fbr_log_header_ok(header);

	_test_log_debug(_LOG, header);

	fbr_log_free_global();

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_init passed");
}
