fiber_test "cstore with backend cluster"

config_add LOG_ALWAYS_FLUSH true

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

# This is the local FiberFS
cstore_init 0

# Two remote FiberFS peers
cstore_init 1
cstore_init 2

# S3
cstore_init 3
cstore_set_s3 3 "" 0 region access_key secret_key

# Set the S3 origin for all cstores
cstore_set_s3 0 $cstore_server_host:3 $cstore_server_port:3 region access_key secret_key
cstore_set_s3 1 $cstore_server_host:3 $cstore_server_port:3 region access_key secret_key
cstore_set_s3 2 $cstore_server_host:3 $cstore_server_port:3 region access_key secret_key

# Build the cluster on the local
cstore_add_cluster 0 $cstore_server_host:0 $cstore_server_port:0
cstore_add_cluster 0 $cstore_server_host:1 $cstore_server_port:1
cstore_add_cluster 0 $cstore_server_host:2 $cstore_server_port:2

# Start the test

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 100

print "### WRITE"

set_var1 $sys_tmpdir "/test1.txt"
sys_write $var1 "test CLUSTER"

set_var2 $sys_tmpdir "/test2.txt"
sys_write $var2 "Number #2"

sleep_ms 100

cstore_debug
cstore_debug 1
cstore_debug 2
cstore_debug 3

equal $cstore_entries:3 4

cstore_clear 0
cstore_clear 1
cstore_clear 2

equal $cstore_entries:0 0
equal $cstore_entries:1 0
equal $cstore_entries:2 0
equal $cstore_entries:3 4

fs_test_release_all

sleep_ms 100

print "### READ"

sys_cat $var1 "test CLUSTER"
sys_cat $var2 "Number #2"

sleep_ms 100

cstore_debug
cstore_debug 1
cstore_debug 2
cstore_debug 3

equal $cstore_entries:3 4

fs_test_stats
