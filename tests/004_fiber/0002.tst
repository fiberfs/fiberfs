fiber_test "Fuse test ls"

fs_mkdir_tmp

fuse_test_ops_mount $fs_tmpdir

fs_ls $fs_tmpdir

set_var1 $fs_tmpdir "/fiber4"
fs_ls $var1

fuse_test_ops_unmount
