fiber_test "cstore server PUT/GET with s3"

cstore_enable_server 127.0.0.1 0
cstore_init 0
cstore_init 1
cstore_set_s3 0 $cstore_1_server_host $cstore_1_server_port

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "test1"

sleep_ms 100

cstore_debug
