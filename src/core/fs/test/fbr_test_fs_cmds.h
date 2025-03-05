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

void fbr_test_fs_fuse_getattr(struct fbr_request *request, fuse_ino_t ino,
	struct fuse_file_info *fi);
void fbr_test_fs_fuse_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name);
void fbr_test_fs_fuse_opendir(struct fbr_request *request, fuse_ino_t ino,
	struct fuse_file_info *fi);
void fbr_test_fs_fuse_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
	struct fuse_file_info *fi);
void fbr_test_fs_fuse_releasedir(struct fbr_request *request, fuse_ino_t ino,
	struct fuse_file_info *fi);
void fbr_test_fs_fuse_forget(struct fbr_request *request, fuse_ino_t ino, uint64_t nlookup);
void fbr_test_fs_fuse_forget_multi(struct fbr_request *request, size_t count,
	struct fuse_forget_data *forgets);

#endif /* FBR_TEST_FS_CMD */

FBR_TEST_FS_CMD(fs_test_init_mount)

FBR_TEST_FS_CMD(fs_test_fuse_mount)
FBR_TEST_FS_CMD(fs_test_fuse_init_root)

FBR_TEST_FS_CMD(fs_test_rw_mount)

FBR_TEST_FS_CMD(fs_test_release_root)
FBR_TEST_FS_CMD(fs_test_dentry_ttl_ms)
FBR_TEST_FS_CMD(fs_test_stats)
FBR_TEST_FS_CMD(fs_test_debug)

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
FBR_TEST_FS_VAR(fs_test_stat_fetch_bytes)
FBR_TEST_FS_VAR(fs_test_stat_read_bytes)
FBR_TEST_FS_VAR(fs_test_stat_write_bytes)

FBR_TEST_FS_CMD(fs_test_path_assert)
FBR_TEST_FS_CMD(fs_test_path)

FBR_TEST_FS_CMD(fs_test_id_assert)

#undef FBR_TEST_FS_CMD
#undef FBR_TEST_FS_VAR

#endif /* FBR_TEST_COREFS_CMDS_H_INCLUDED */
