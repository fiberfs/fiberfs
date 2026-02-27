fiber_test "Log rlog"

config_add LOG_SIZE 150000
config_add LOG_BUFFER_SIZE 1024

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir

test_log_rlog

test_log_debug

fuse_test_unmount
