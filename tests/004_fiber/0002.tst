fiber_test "Fuse test ls"

fs_mkdir_tmp

fuse_test_ops_mount $fs_tmpdir

fs_ls $fs_tmpdir "..:dir .:dir fiber1:file fiber2:file fiber3:file fiber4:dir fiber5:file"

set_var1 $fs_tmpdir "/fiber4"
fs_ls $var1 "..:dir .:dir fiber41:file fiber42:file fiber43:file"

fuse_test_ops_unmount
