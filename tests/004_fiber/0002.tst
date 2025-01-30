fiber_test "Fuse test ls"

set_timeout_sec 2

fs_mkdir_tmp

fuse_test_mount $fs_tmpdir
#fs_ls $fs_tmpdir
fuse_test_unmount
