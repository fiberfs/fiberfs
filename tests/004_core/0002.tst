fiber_test "Fuse test ls"

sys_mkdir_tmp

fuse_test_ops_mount $sys_tmpdir

sys_ls $sys_tmpdir "..:dir .:dir fiber1:file fiber2:file fiber3:file fiber4:dir fiber5:file"

set filename $sys_tmpdir "/fiber4"
sys_ls $filename "..:dir .:dir fiber41:file fiber42:file fiber43:file"

sleep_ms 100

fuse_test_ops_unmount
