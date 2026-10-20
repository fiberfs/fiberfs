fiber_test "cstore backend and s3 and no auth"

cstore_init 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 1
cstore_init 2

cstore_set_s3 0 $cstore_server_host:2 $cstore_server_port:2
cstore_set_s3 1 $cstore_server_host:2 $cstore_server_port:2
cstore_mock_s3 2

cstore_add_cluster 0 $cstore_server_host:1 $cstore_server_port:1

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 10

print "### WRITE"

set file $sys_tmpdir "/test.txt"
sys_write $file "test_ABC no sign"

sleep_ms 10

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:2 3

print "### READ"

cstore_clear 0
cstore_clear 1
equal $cstore_entries:0 0
equal $cstore_entries:1 0

fs_test_release_all_wait
sleep_ms 10

sys_cat $file "test_ABC no sign"

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:2 3

equal $cstore_stat_roots:2 1
equal $cstore_stat_indexes:2 1
equal $cstore_stat_chunks:2 1
equal $cstore_stat_chunks_fullfile:2 1

equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0
equal $cstore_stat_http_400:2 0
equal $cstore_stat_http_500:2 0

fs_test_stats
fs_test_release_all_wait 1
equal $fs_test_stat_files_inodes 0

fuse_test_unmount
