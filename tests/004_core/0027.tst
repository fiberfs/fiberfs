fiber_test "Directory read test"

# Init

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir
fs_test_dentry_ttl_ms 0

config_add FS_WBUFFER_ALLOC_SIZE 3

# Operations

set_var1 $sys_tmpdir "/test1.txt"
sys_write $var1 "test11" "1one"

set_var2 $sys_tmpdir "/test2.txt"
sys_write $var2 "tes" "t22" "2two" "444" "TWO"

fs_test_release_all
sleep_ms 100

sys_cat $var1 "test111one"
sys_cat $var2 "test222two444TWO"

# Cleanup

sleep_ms 100
fs_test_stats
fs_test_debug

fs_test_release_all 1

sleep_ms 200
fs_test_stats
fs_test_debug

cstore_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0
equal $cstore_stat_chunks 7

fuse_test_unmount
