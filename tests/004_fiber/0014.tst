fiber_test "RW test"

# Init

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

sys_ls $sys_tmpdir "..:dir .:dir"

# Cleanup

sleep_ms 100

fs_test_stats
fs_test_debug

fuse_test_unmount
