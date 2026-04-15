fiber_test "cstore server PUT/GET with s3"

cstore_init 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 1
cstore_set_s3 0 $cstore_server_host:1 $cstore_server_port:1 region access_key secret_key
cstore_set_s3 1 "" 0 region access_key secret_key

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

print "### WRITE 2 CHUNKS"

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "test1test2test3"
sys_append $var1 "test4test5"

sleep_ms 100

cstore_debug
cstore_debug 1

equal $cstore_entries:0 6
equal $cstore_stat_chunks:0 2
equal $cstore_stat_indexes:0 3
equal $cstore_stat_roots:0 1

equal $cstore_entries:1 4
equal $cstore_stat_chunks:1 2
equal $cstore_stat_indexes:1 1
equal $cstore_stat_roots:1 1

cstore_clear 0
equal $cstore_entries:0 0
fs_test_release_all
sleep_ms 100

print "### READ 2 CHUNKS FROM CSTORE_1"

sys_cat $var1 "test1test2test3test4test5"

sleep_ms 100
cstore_debug
cstore_debug 1
equal $cstore_entries:0 4

fuse_test_unmount
