/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef FBR_TEST_COREFS_CMDS_H_INCLUDED
#define FBR_TEST_COREFS_CMDS_H_INCLUDED

#ifndef FBR_TEST_FS_CMD

#include "core/fs/fbr_fs.h"
#include "test/fbr_test.h"

#define FBR_TEST_FS_CMD(cmd)		fbr_test_cmd_f fbr_cmd_##cmd;
#define FBR_TEST_FS_VAR(var)		fbr_test_var_f fbr_var_##var;

void __fbr_attr_printf(1) fbr_test_fs_logger(const char *fmt, ...);
void fbr_test_fs_stats(struct fbr_fs *fs);
void fbr_test_fs_fuse_getattr(struct fbr_request *request, fuse_ino_t ino,
	struct fuse_file_info *fi);
void fbr_test_fs_fuse_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name);
void fbr_test_fs_fuse_opendir(struct fbr_request *request, fuse_ino_t ino,
	struct fuse_file_info *fi);
void fbr_test_fs_fuse_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size,
	off_t off, struct fuse_file_info *fi);
void fbr_test_fs_fuse_releasedir(struct fbr_request *request, fuse_ino_t ino,
	struct fuse_file_info *fi);
void fbr_test_fs_fuse_read(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
	struct fuse_file_info *fi);
void fbr_test_fs_fuse_forget(struct fbr_request *request, fuse_ino_t ino, uint64_t nlookup);
void fbr_test_fs_fuse_forget_multi(struct fbr_request *request, size_t count,
	struct fuse_forget_data *forgets);
void fbr_test_fs_inodes_debug(struct fbr_fs *fs);
void fbr_test_fs_dindex_debug(struct fbr_fs *fs);
struct fbr_fs * fbr_test_fs_alloc(void);

size_t fbr_test_fs_count_chunks(struct fbr_file *file);

#endif /* FBR_TEST_FS_CMD */

FBR_TEST_FS_CMD(fs_test_init_mount)

FBR_TEST_FS_CMD(fs_test_fuse_mount)
FBR_TEST_FS_CMD(fs_test_fuse_init_root)

FBR_TEST_FS_CMD(fs_test_rw_mount)
FBR_TEST_FS_CMD(fs_test_rw_buffer_size)

FBR_TEST_FS_CMD(fs_test_release_all)
FBR_TEST_FS_CMD(fs_test_lru_purge)
FBR_TEST_FS_CMD(fs_test_assert_root)
FBR_TEST_FS_CMD(fs_test_dentry_ttl_ms)
FBR_TEST_FS_CMD(fs_test_stats)
FBR_TEST_FS_CMD(fs_test_debug)
FBR_TEST_FS_CMD(fs_test_allow_crash)

FBR_TEST_FS_CMD(_fs_test_take_dir)
FBR_TEST_FS_CMD(_fs_test_release_dir)
FBR_TEST_FS_CMD(_fs_test_take_file)
FBR_TEST_FS_CMD(_fs_test_release_file)

FBR_TEST_FS_VAR(fs_test_stat_directories)
FBR_TEST_FS_VAR(fs_test_stat_directories_dindex)
FBR_TEST_FS_VAR(fs_test_stat_directories_total)
FBR_TEST_FS_VAR(fs_test_stat_directory_refs)
FBR_TEST_FS_VAR(fs_test_stat_files)
FBR_TEST_FS_VAR(fs_test_stat_files_inodes)
FBR_TEST_FS_VAR(fs_test_stat_files_total)
FBR_TEST_FS_VAR(fs_test_stat_file_refs)
FBR_TEST_FS_VAR(fs_test_stat_requests_alloc)
FBR_TEST_FS_VAR(fs_test_stat_requests_freed)
FBR_TEST_FS_VAR(fs_test_stat_requests_recycled)
FBR_TEST_FS_VAR(fs_test_stat_fetch_bytes)
FBR_TEST_FS_VAR(fs_test_stat_read_bytes)
FBR_TEST_FS_VAR(fs_test_stat_write_bytes)
FBR_TEST_FS_VAR(fs_test_stat_store_bytes)
FBR_TEST_FS_VAR(fs_test_stat_store_index_bytes)
FBR_TEST_FS_VAR(fs_test_stat_store_root_bytes)
FBR_TEST_FS_VAR(fs_test_stat_flushes)

FBR_TEST_FS_CMD(fs_test_path_assert)
FBR_TEST_FS_CMD(fs_test_path)

FBR_TEST_FS_CMD(fs_test_body)
FBR_TEST_FS_CMD(fs_test_body_fio)
FBR_TEST_FS_CMD(fs_test_body_pfio)
FBR_TEST_FS_CMD(fs_test_body_spfio)
FBR_TEST_FS_CMD(fs_test_body_spfio_error)
FBR_TEST_FS_CMD(fs_test_body_pwbuffer)
FBR_TEST_FS_CMD(fs_test_body_spwbuffer)
FBR_TEST_FS_CMD(fs_test_body_spwbuffer_error)

FBR_TEST_FS_CMD(fs_test_root_parallel)
FBR_TEST_FS_CMD(fs_test_directory_parallel)
FBR_TEST_FS_CMD(fs_test_directory_release)
FBR_TEST_FS_CMD(fs_test_directory_release_ttl)

#undef FBR_TEST_FS_CMD
#undef FBR_TEST_FS_VAR

#endif /* FBR_TEST_COREFS_CMDS_H_INCLUDED */
