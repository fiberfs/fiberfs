fiber_test "FS init"

sys_mkdir_tmp
fs_test_init_mount $sys_tmpdir

fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 2
equal $fs_test_stat_files 4
equal $fs_test_stat_files_inodes 2

fs_test_lru_purge 1

fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 1
equal $fs_test_stat_files 4
equal $fs_test_stat_files_inodes 1

fs_test_assert_root

fs_test_release_all 1

fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
