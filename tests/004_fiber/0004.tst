fiber_test "Fuse sim"

fs_mkdir_tmp

fs_test_simple_mount $fs_tmpdir

fs_test_stats

equal $fs_test_stat_directories 1
equal $fs_test_stat_files 2

fs_test_release_root

fs_test_stats

equal $fs_test_stat_directories 0
equal $fs_test_stat_files 0

fuse_test_unmount
