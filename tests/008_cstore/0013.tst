fiber_test "cstore server PUT/GET with backend and s3"

config_add CONFIG_UPDATE_INTERVAL 1
config_add FORCE_CHUNK_WRITE true

cstore_init 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 1
cstore_init 2

cstore_set_s3 0 $cstore_server_host:2 $cstore_server_port:2 region access_key secret_key
cstore_set_s3 1 $cstore_server_host:2 $cstore_server_port:2 region access_key secret_key
cstore_set_s3 2 "" 0 region access_key secret_key

cstore_add_cluster 0 $cstore_server_host:1 $cstore_server_port:1

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 100

print "### WRITE"

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "test_ABC"

sleep_ms 100

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:0 4
equal $cstore_entries:1 4
equal $cstore_entries:2 3

print "### WRITE OVER"

sys_write $var1 "XYZ 22"

sleep_ms 100

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:0 6
equal $cstore_entries:1 6
equal $cstore_entries:2 3

cstore_clear 0
cstore_clear 1
equal $cstore_entries:0 0
equal $cstore_entries:1 0
equal $cstore_entries:2 3
fs_test_release_all

sleep_ms 100

print "### READ"

sys_cat $var1 "XYZ 22"

sleep_ms 100

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:0 3
equal $cstore_entries:1 3
equal $cstore_entries:2 3

cstore_clear 0
equal $cstore_entries:0 0
equal $cstore_entries:1 3
fs_test_release_all

sleep_ms 100

print "### READ AGAIN"

sys_cat $var1 "XYZ 22"

sleep_ms 100

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:0 3
equal $cstore_entries:1 3
equal $cstore_entries:2 3

fs_test_stats
