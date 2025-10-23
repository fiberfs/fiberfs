fiber_test "cstore server PUT/GET with backend and s3"

cstore_init 0

cstore_enable_server 127.0.0.1 0
cstore_init 1
cstore_init 2

cstore_set_s3 0 $cstore_2_server_host $cstore_2_server_port
cstore_set_s3 1 $cstore_2_server_host $cstore_2_server_port

cstore_add_cluster 0 $cstore_1_server_host $cstore_1_server_port

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 100

print "### WRITE"

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "test_ABC"

sleep_ms 100

#cstore_clear 0
#equal $cstore_0_entries 0
#fs_test_release_all
#sleep_ms 100

print "### READ"

sys_cat $var1 "test_ABC"

sleep_ms 100

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_0_entries 4
equal $cstore_1_entries 4
equal $cstore_2_entries 3
