fiber_test "Fuse and fs"

fs_mkdir_tmp

fs_test_fuse_mount $fs_tmpdir

fs_test_stats

fs_ls $fs_tmpdir

set_var1 $fs_tmpdir "/fiber2"
fs_cat $var1

fs_test_release_root

fs_test_stats

equal $fs_test_stat_directories 0
equal $fs_test_stat_directory_refs 0

# TODO page cache... this is unstable, also fs_cat can be slow to release
sleep_ms 100
equal $fs_test_stat_files 1
equal $fs_test_stat_file_refs 1

fuse_test_unmount
