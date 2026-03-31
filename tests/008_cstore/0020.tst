fiber_test "cstore with ipv6 cluster loop prevention"

config_add LOG_ALWAYS_FLUSH true

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "::1"
config_add CSTORE_SERVER_PORT 0

# Local cstore
cstore_init 0

# S3
cstore_init 1
cstore_set_s3 1 "" 0 region access_key secret_key

# Set the S3 origin for cstore
cstore_set_s3 0 $cstore_1_server_host $cstore_1_server_port region access_key secret_key $cstore_1_server_tls

# Make the cluster loop
cstore_add_cluster 0 $cstore_0_server_host $cstore_0_server_port

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

equal $cstore_0_entries 6
equal $cstore_1_entries 4

cstore_clear 0

equal $cstore_0_entries 0

fs_test_release_all

sleep_ms 100

print "### READ"

sys_cat $var1 "test CLUSTER"
sys_cat $var2 "Number #2"

sleep_ms 100

cstore_debug
cstore_debug 1

equal $cstore_0_entries 4
equal $cstore_1_entries 4

fs_test_stats
