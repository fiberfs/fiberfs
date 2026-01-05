fiber_test "cstore server with TLS"

cstore_init 0
cstore_enable_server 127.0.0.1 0 1
cstore_init 1
cstore_set_s3 0 $cstore_1_server_host $cstore_1_server_port region access_key secret_key $cstore_1_server_tls
cstore_set_s3 1 "" 0 region access_key secret_key

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "testing 123"

sleep_ms 100

cstore_debug
cstore_debug 1

equal $cstore_1_entries 3
