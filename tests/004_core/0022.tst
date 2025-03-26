fiber_test "RW test"

# Init

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir
fs_test_dentry_ttl_ms 0

# Operations

sys_ls $sys_tmpdir "..:dir .:dir"

sleep_ms 100

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "test1" "test2" "test3"

equal $fs_test_stat_write_bytes 15

sys_ls $sys_tmpdir "..:dir .:dir test.txt:file"
sys_cat $var1 "test1test2test3"

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

fuse_test_unmount
