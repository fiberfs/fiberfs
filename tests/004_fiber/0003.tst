fiber_test "Fuse test cat"

fs_mkdir_tmp

fuse_test_ops_mount $fs_tmpdir

fs_ls $fs_tmpdir

set_var2 $fs_tmpdir "/fiber4/fiber42"
fs_cat $var2 "fiber42"

set_var3 $fs_tmpdir "/fiber2"
fs_cat $var3 "fiber2"

fuse_test_ops_unmount
