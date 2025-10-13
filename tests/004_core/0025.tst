fiber_test "RW test"

# Init

set_timeout_sec 20
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir
fs_test_dentry_ttl_ms 0

# Operations

sys_ls $sys_tmpdir "..:dir .:dir"

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "test1" "test2" "test3"

equal $fs_test_stat_write_bytes 15

sys_ls $sys_tmpdir "..:dir .:dir test.txt:file"
sys_stat_size $var1 15
sys_cat $var1 "test1test2test3"

equal $fs_test_stat_read_bytes 15

# Cleanup

sleep_ms 100
fs_test_stats
fs_test_debug

fs_test_release_all 1

sleep_ms 200
fs_test_stats
fs_test_debug

cstore_debug

equal $cstore_stat_chunk_write_bytes 15
equal $cstore_stat_chunk_read_bytes 15

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
