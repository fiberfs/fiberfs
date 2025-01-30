fiber_test "Fuse test ls"

fs_mkdir_tmp

fuse_test1_mount $fs_tmpdir
#fs_ls $fs_tmpdir
fuse_test1_unmount
