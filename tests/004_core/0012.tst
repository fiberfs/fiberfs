fiber_test "File reading simple"

# Init

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir
fs_test_fuse_init_root

# Do read

set_var1 $sys_tmpdir "/fiber_small"
sys_stat_size $var1 101
sys_cat_md5 $var1 525cce3d8c3eaf36a756a91fcb996d59

# Cleanup

sleep_ms 100
fs_test_stats
fs_test_debug

fs_test_release_all 1

sleep_ms 100
fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0
equal $fs_test_stat_read_bytes 101

fuse_test_unmount
