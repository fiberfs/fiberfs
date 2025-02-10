fiber_test "Fuse sim"

fs_mkdir_tmp

fs_test_simple_mount $fs_tmpdir

fuse_test_unmount
