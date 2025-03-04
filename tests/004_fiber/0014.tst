fiber_test "RW test"

# Init

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Cleanup

fuse_test_unmount
