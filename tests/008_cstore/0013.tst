fiber_test "cstore server PUT/GET with backend and s3"

config_add CONFIG_UPDATE_INTERVAL 1
config_add FORCE_CHUNK_WRITE true
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

set file $sys_tmpdir "/test.txt"
sys_write $file "test_ABC"

sleep_ms 10

cstore_debug
cstore_debug 1
cstore_debug 2

greater_equal $cstore_entries:0 4
greater_equal $cstore_entries:1 4
equal $cstore_entries:2 3

print "### WRITE OVER"

sys_write $file "XYZ 22"

sleep_ms 10

cstore_debug
cstore_debug 1
cstore_debug 2

greater_equal $cstore_entries:0 6
greater_equal $cstore_entries:1 6
equal $cstore_entries:2 3

cstore_clear 0
cstore_clear 1
equal $cstore_entries:0 0
equal $cstore_entries:1 0
equal $cstore_entries:2 3
fs_test_release_all_wait

sleep_ms 10

print "### READ"

sys_cat $file "XYZ 22"

sleep_ms 10

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:0 3
equal $cstore_entries:1 3
equal $cstore_entries:2 3

cstore_clear 0
equal $cstore_entries:0 0
equal $cstore_entries:1 3
fs_test_release_all_wait

sleep_ms 10

print "### READ AGAIN"

sys_cat $file "XYZ 22"

sleep_ms 10

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:0 3
equal $cstore_entries:1 3
equal $cstore_entries:2 3

equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0
equal $cstore_stat_http_400:2 0
equal $cstore_stat_http_500:2 0

fs_test_stats

fuse_test_unmount
