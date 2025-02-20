fiber_test "Fuse test ls"

sys_mkdir_tmp

fuse_test_ops_mount $sys_tmpdir

sys_ls $sys_tmpdir "..:dir .:dir fiber1:file fiber2:file fiber3:file fiber4:dir fiber5:file"

set_var1 $sys_tmpdir "/fiber4"
sys_ls $var1 "..:dir .:dir fiber41:file fiber42:file fiber43:file"

fuse_test_ops_unmount
