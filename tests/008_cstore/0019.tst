fiber_test "cstore with cluster loop"

set_timeout_sec 30

config_add LOG_ALWAYS_FLUSH true

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

# Local cstore
cstore_init 0

# S3
cstore_init 1
cstore_mock_s3 1 region access_key secret_key

# Set the S3 origin for cstore
cstore_set_s3 0 $cstore_server_host:1 $cstore_server_port:1 region access_key secret_key $cstore_server_tls:1

# Make the cluster loop
cstore_debug_allow_loop
cstore_add_cluster 0 $cstore_server_host:0 $cstore_server_port:0

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

equal $cstore_entries:1 4
equal $cstore_stat_chunks:1 2
equal $cstore_stat_indexes:1 1
equal $cstore_stat_roots:1 1

fs_test_release_all

sleep_ms 100

print "### READ"

sys_cat $var1 "test CLUSTER"
sys_cat $var2 "Number #2"

sleep_ms 100

cstore_debug
cstore_debug 1

equal $cstore_entries:1 4

fs_test_stats

fuse_test_unmount
