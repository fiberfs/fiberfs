/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef FBR_TEST_COREFS_CMDS_H_INCLUDED
#define FBR_TEST_COREFS_CMDS_H_INCLUDED

#ifndef FBR_TEST_FS_CMD

#include "test/fbr_test.h"

#define FBR_TEST_FS_CMD(cmd)		fbr_test_cmd_f fbr_cmd_##cmd;
#define FBR_TEST_FS_VAR(var)		fbr_test_var_f fbr_var_##var;

#endif /* FBR_TEST_FS_CMD */

FBR_TEST_FS_CMD(fs_test_init_mount)

FBR_TEST_FS_CMD(fs_test_fuse_mount)

FBR_TEST_FS_CMD(fs_test_release_root)
FBR_TEST_FS_CMD(fs_test_stats)

FBR_TEST_FS_VAR(fs_test_stat_directories)
FBR_TEST_FS_VAR(fs_test_stat_directories_total)
FBR_TEST_FS_VAR(fs_test_stat_directory_refs)
FBR_TEST_FS_VAR(fs_test_stat_files)
FBR_TEST_FS_VAR(fs_test_stat_files_total)
FBR_TEST_FS_VAR(fs_test_stat_file_refs)

#undef FBR_TEST_FS_CMD
#undef FBR_TEST_FS_VAR

#endif /* FBR_TEST_COREFS_CMDS_H_INCLUDED */
