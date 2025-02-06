fiber_test "Fuse sim"

fs_mkdir_tmp

fuse_test_sim_mount $fs_tmpdir

fuse_test_unmount
