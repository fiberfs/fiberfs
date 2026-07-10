fiber_test "cstore server with backend CDN and s3"

# Config
config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

# Self
cstore_init 0

# Cluster peer
cstore_init 1

# CDN
cstore_init 2

# S3
cstore_init 3
cstore_set_s3 0 $cstore_server_host:3 $cstore_server_port:3 region access_key secret_key
cstore_set_s3 1 $cstore_server_host:3 $cstore_server_port:3 region access_key secret_key
cstore_set_s3 2 $cstore_server_host:3 $cstore_server_port:3 region access_key secret_key
cstore_mock_s3 3 region access_key secret_key

# Build the cluster
cstore_add_cluster 0 $cstore_server_host:0 $cstore_server_port:0
cstore_add_cluster 0 $cstore_server_host:1 $cstore_server_port:1

# Add CDN
cstore_add_cdn 0 $cstore_server_host:2 $cstore_server_port:2
cstore_add_cdn 1 $cstore_server_host:2 $cstore_server_port:2

# Mount
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 20

print "### WRITE"

set_var1 $sys_tmpdir "/testCDN.txt"
sys_write $var1 "test_ABC"

sleep_ms 20

cstore_debug
cstore_debug 1
cstore_debug 2
cstore_debug 3

greater_than $cstore_entries:0 0
equal $cstore_entries:2 0
equal $cstore_entries:3 3

print "### CLEAR and READ"

cstore_clear 0
cstore_clear 1
fs_test_release_all_wait

equal $cstore_entries:0 0
equal $cstore_entries:1 0

sleep_ms 20

sys_ls $sys_tmpdir

sleep_ms 20

cstore_debug 2

equal $cstore_entries:2 1
equal $cstore_stat_roots:2 0
equal $cstore_stat_indexes:2 1

print "### CLEANUP"

fs_test_stats

fs_test_release_all_wait 1
equal $fs_test_stat_files_inodes 0

fuse_test_unmount
