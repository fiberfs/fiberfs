fiber_test "Fuse test mounting"

fs_mkdir_tmp

fuse_test_mount $fs_tmpdir
fuse_test_unmount
