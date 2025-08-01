fiber_test "mkdir op test"

sys_mkdir_tmp
mkdir_op_test_mount $sys_tmpdir

set_var1 $sys_tmpdir "/test_two"
sys_mkdir $var1
sleep_ms 10

mkdir_test_fail $var1
sleep_ms 10

set_var2 "test_33333"
mkdir_test_remote $var2
sleep_ms 10

set_var3 $sys_tmpdir "/" $var2
mkdir_test_fail $var3
sleep_ms 10

set_var4 $sys_tmpdir "/test_error"
mkdir_test_fail $var4
sleep_ms 10

#set_var5 $sys_tmpdir "/test_5"
#sys_mkdir $var5
#sleep_ms 10

dstore_debug

equal $dstore_stat_roots 4
equal $dstore_stat_indexes 4

fuse_test_unmount
