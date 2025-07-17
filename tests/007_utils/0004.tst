fiber_test "Log rlog"

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir

test_log_rlog

fuse_test_unmount
