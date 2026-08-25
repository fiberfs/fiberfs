fiber_test "Fuse test cat"

sys_mkdir_tmp

fuse_test_ops_mount $sys_tmpdir

sys_ls $sys_tmpdir

set filename $sys_tmpdir "/fiber4/fiber42"
sys_cat $filename "fiber42"

set filename2 $sys_tmpdir "/fiber2"
sys_cat $filename2 "fiber2"

equal $fuse_test_ops_open_count 0

fuse_test_ops_unmount
