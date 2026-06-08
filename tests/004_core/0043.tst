fiber_test "Resizing"

# Init
config_add DEBUG_FS_WBUFFER_ALLOC_SIZE 3

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### Extend"

set_var1 $sys_tmpdir "/somefile"
sys_truncate $var1 16

fs_test_release_all_wait
sleep_ms 20

sys_cat_md5 $var1 4ae71336e44bf9bf79d2752e234818a5

print "### Truncate"

sleep_ms 20

sys_truncate $var1 5

fs_test_release_all_wait
sleep_ms 20

sys_cat_md5 $var1 ca9c491ac66b2c62500882e93f3719a8

print "### Write"

sleep_ms 20

sys_write_seek $var1 3 "ABC" "123" "ZZZ"
sys_truncate $var1 15

fs_test_release_all_wait
sleep_ms 20

sys_cat_md5 $var1 808a50a8621d968b9b69e97af4eaaf9b

equal $cstore_stat_chunks:0 3

print "### Truncate 2"

sleep_ms 20

sys_truncate $var1 5

fs_test_release_all_wait
sleep_ms 20

sys_cat_md5 $var1 536629b0ae03b922650462e857fc90e1

equal $cstore_stat_chunks:0 1

# Cleanup

print "### CLEANUP"

fs_test_release_all_wait 1

sleep_ms 20
fs_test_stats
fs_test_debug
cstore_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
