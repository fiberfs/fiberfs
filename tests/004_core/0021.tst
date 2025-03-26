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

# Cleanup

sleep_ms 100
fs_test_stats
fs_test_debug

fs_test_release_all

sleep_ms 100
fs_test_stats
fs_test_debug

fuse_test_unmount
