fiber_test "Fuse test cat"

sys_mkdir_tmp

fuse_test_ops_mount $sys_tmpdir

sys_ls $sys_tmpdir

set_var2 $sys_tmpdir "/fiber4/fiber42"
sys_cat $var2 "fiber42"

set_var3 $sys_tmpdir "/fiber2"
sys_cat $var3 "fiber2"

sleep_ms 200

fuse_test_ops_unmount
