fiber_test "cstore server with TLS"

skip_if_not $tls_enabled

config_add LOG_ALWAYS_FLUSH true
config_add CSTORE_SERVER_TLS true
cstore_tls_timeout

cstore_init 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 1
cstore_set_s3 0 $cstore_server_host:1 $cstore_server_port:1 region access_key secret_key $cstore_server_tls:1
cstore_mock_s3 1 region access_key secret_key

print "### WRITE INDEX AND FILE"

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "testing 123"

sleep_ms 100

cstore_debug
cstore_debug 1

equal $cstore_entries:1 3

print "### DROP CSTORE_0 CACHE"

cstore_clear 0
equal $cstore_entries:0 0
fs_test_release_all

sleep_ms 100

print "### READ INDEX AND FILE"

sys_cat $var1 "testing 123"

sleep_ms 100

cstore_debug
cstore_debug 1

equal $cstore_entries:0 3
