fiber_test "cstore server PUT/GET with s3"

cstore_init 0
cstore_enable_server 127.0.0.1 0
cstore_init 1
cstore_set_s3 0 $cstore_1_server_host $cstore_1_server_port

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

print "### WRITE 2 CHUNKS"

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "test1test2test3"
sys_append $var1 "test4test5"

cstore_dirty_rm 0

print "### READ 2 CHUNKS FROM CSTORE_1"

sys_cat $var1 "test1test2test3test4test5"

#fs_test_release_all
#sleep_ms 100

#print "### READ 2 CHUNKS FROM CSTORE_0"

#sys_cat $var1 "test1test2test3test4test5"

sleep_ms 100

cstore_debug
cstore_debug 1
