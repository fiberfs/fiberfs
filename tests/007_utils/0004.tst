fiber_test "Log rlog"

test_log_size 150000

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir

test_log_rlog

test_log_debug

fuse_test_unmount
