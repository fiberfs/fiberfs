fiber_test "cstore server with cluster, CDN, S3 via config with TLS"

# Config
config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0
config_add CSTORE_SERVER_TLS true
config_add ALLOW_CDN_PUT true
config_add ALLOW_CDN_DELETE true
config_add ALLOW_CDN_ROOT_GET true
config_add CSTORE_DELETE_CACHE true

# Self
cstore_init 0

# Cluster peer
cstore_init 1

# CDN
cstore_init 2

# S3
cstore_init 3

# Configure non main cstores
cstore_set_s3 1 $cstore_server_host:3 $cstore_server_port:3 REGION ACCESS_KEY SECRET_KEY \
	$cstore_server_tls:3 /ABC/123
cstore_set_s3 2 $cstore_server_host:3 $cstore_server_port:3 REGION ACCESS_KEY SECRET_KEY \
	$cstore_server_tls:3 /ABC/123
cstore_mock_s3 3 REGION ACCESS_KEY SECRET_KEY /ABC/123
cstore_add_cdn 1 $cstore_server_host:2 $cstore_server_port:2 $cstore_server_tls:2

# Configure main cstore via config
config_add TEST_AUTOINIT true
config_add S3_HOST $cstore_server_host:3
config_add S3_PORT $cstore_server_port:3
config_add S3_REGION REGION
config_add S3_ACCESS_KEY ACCESS_KEY
config_add S3_SECRET_KEY SECRET_KEY
config_add S3_PREFIX /ABC/123
config_add CLUSTER_TLS true
set_var2 $cstore_server_host:0 ":" $cstore_server_port:0 ", " \
	$cstore_server_host:1 ":" $cstore_server_port:1
config_add CLUSTER $var2
set_var2 $cstore_server_host:2 ":" $cstore_server_port:2
config_add CDN_ENDPOINT $var2

# Mount
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 20

print "### WRITE"

set_var1 $sys_tmpdir "/testCDN_config.txt"
sys_write $var1 "test_ABC config based"

sleep_ms 20

cstore_debug
cstore_debug 1
cstore_debug 2
cstore_debug 3

greater_than $cstore_entries:0 0
less_equal $cstore_entries:0 3
less_equal $cstore_entries:1 3
equal $cstore_entries:2 2
equal $cstore_entries:3 3

print "### CLEANUP"

fs_test_stats

fs_test_release_all_wait 1
equal $fs_test_stat_files_inodes 0

fuse_test_unmount
