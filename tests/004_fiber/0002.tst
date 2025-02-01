fiber_test "Fuse test ls"

fs_mkdir_tmp

fuse_test_ops_mount $fs_tmpdir
fs_ls $fs_tmpdir
fuse_test_ops_unmount
