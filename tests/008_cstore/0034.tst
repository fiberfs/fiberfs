fiber_test "cstore server json chars"

config_add S3_SKIP_CONTENT_HASH false
config_add CSTORE_VALIDATE_CONTENT_HASH true

cstore_init 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 1
cstore_init 2

cstore_set_s3 0 $cstore_server_host:2 $cstore_server_port:2 region access_key secret_key
cstore_set_s3 1 $cstore_server_host:2 $cstore_server_port:2 region access_key secret_key
cstore_mock_s3 2 region access_key secret_key

cstore_add_cluster 0 $cstore_server_host:1 $cstore_server_port:1

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 10

print "### WRITE"

set file $sys_tmpdir "/\"test\".txt"
sys_write $file "test_QUOTE"

sleep_ms 10

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:2 3

cstore_clear 0
cstore_clear 1
equal $cstore_entries:0 0
equal $cstore_entries:1 0
equal $cstore_entries:2 3
fs_test_release_all_wait

sleep_ms 10

print "### READ"

sys_cat $file "test_QUOTE"

sleep_ms 10

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0
equal $cstore_stat_http_400:2 0
equal $cstore_stat_http_500:2 0

fs_test_stats
fs_test_release_all_wait

equal $fs_test_stat_files_inodes 1

fuse_test_unmount
