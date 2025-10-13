/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_COREFS_CMDS_H_INCLUDED
#define _FBR_TEST_COREFS_CMDS_H_INCLUDED

#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test_cmd_declare.h"

void fbr_test_fs_stats(struct fbr_fs *fs);
void fbr_test_fs_inodes_debug(struct fbr_fs *fs);
void fbr_test_fs_dindex_debug(struct fbr_fs *fs);
struct fbr_fs * fbr_test_fs_alloc(void);
size_t fbr_test_fs_read(struct fbr_fs *fs, struct fbr_file *file, size_t offset, char *buffer,
	size_t buffer_len);

size_t fbr_test_fs_count_chunks(struct fbr_file *file);
struct fbr_chunk *fbr_test_fs_get_chunk(struct fbr_file *file, size_t position);

#endif /* _FBR_TEST_COREFS_CMDS_H_INCLUDED */

FBR_TEST_CMD(fs_test_init_mount)

FBR_TEST_CMD(fs_test_fuse_mount)
FBR_TEST_CMD(fs_test_fuse_init_root)

FBR_TEST_CMD(fs_test_rw_mount)
FBR_TEST_CMD(fs_test_rw_buffer_size)

FBR_TEST_CMD(fs_test_release_all)
FBR_TEST_CMD(fs_test_lru_purge)
FBR_TEST_CMD(fs_test_assert_root)
FBR_TEST_CMD(fs_test_dentry_ttl_ms)
FBR_TEST_CMD(fs_test_stats)
FBR_TEST_CMD(fs_test_debug)
FBR_TEST_CMD(fs_test_allow_crash)

FBR_TEST_CMD(_fs_test_take_dir)
FBR_TEST_CMD(_fs_test_release_dir)
FBR_TEST_CMD(_fs_test_take_file)
FBR_TEST_CMD(_fs_test_release_file)

FBR_TEST_VAR(fs_test_stat_directories)
FBR_TEST_VAR(fs_test_stat_directories_dindex)
FBR_TEST_VAR(fs_test_stat_directories_total)
FBR_TEST_VAR(fs_test_stat_directory_refs)
FBR_TEST_VAR(fs_test_stat_files)
FBR_TEST_VAR(fs_test_stat_files_inodes)
FBR_TEST_VAR(fs_test_stat_files_total)
FBR_TEST_VAR(fs_test_stat_file_refs)
FBR_TEST_VAR(fs_test_stat_requests_alloc)
FBR_TEST_VAR(fs_test_stat_requests_freed)
FBR_TEST_VAR(fs_test_stat_requests_recycled)
FBR_TEST_VAR(fs_test_stat_read_bytes)
FBR_TEST_VAR(fs_test_stat_write_bytes)
FBR_TEST_VAR(fs_test_stat_store_index_bytes)
FBR_TEST_VAR(fs_test_stat_store_root_bytes)
FBR_TEST_VAR(fs_test_stat_appends)
FBR_TEST_VAR(fs_test_stat_flushes)

FBR_TEST_CMD(fs_test_path_assert)
FBR_TEST_CMD(fs_test_path)

FBR_TEST_CMD(fs_test_body)
FBR_TEST_CMD(fs_test_body_fio)
FBR_TEST_CMD(fs_test_body_hole)

FBR_TEST_CMD(fs_test_body_pfio)
FBR_TEST_CMD(fs_test_body_spfio)
FBR_TEST_CMD(fs_test_body_spfio_error)

FBR_TEST_CMD(fs_test_body_pwbuffer)
FBR_TEST_CMD(fs_test_body_spwbuffer)
FBR_TEST_CMD(fs_test_body_spwbuffer_error)

FBR_TEST_CMD(fs_test_root_parallel)
FBR_TEST_CMD(fs_test_directory_parallel)
FBR_TEST_CMD(fs_test_directory_release)
FBR_TEST_CMD(fs_test_directory_release_ttl)
