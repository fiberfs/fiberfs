fiber_test "Fuse test mounting"

sys_mkdir_tmp

fuse_test_mount $sys_tmpdir
fuse_test_unmount
