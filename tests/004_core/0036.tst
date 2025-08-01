fiber_test "mkdir op test"

sys_mkdir_tmp
mkdir_op_test_mount $sys_tmpdir

set_var1 $sys_tmpdir "/test_two"
sys_mkdir $var1

mkdir_test_fail $var1

dstore_debug

fuse_test_unmount
