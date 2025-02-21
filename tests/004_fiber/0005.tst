fiber_test "Fuse and fs"

sys_mkdir_tmp

fs_test_fuse_mount $sys_tmpdir

sys_ls $sys_tmpdir

fs_test_release_root

sleep_ms 100

fs_test_stats

equal $fs_test_stat_directories 0

fuse_test_unmount
