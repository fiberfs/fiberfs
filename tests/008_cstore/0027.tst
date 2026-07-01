fiber_test "cstore with s3 preifx"

cstore_init 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 1
cstore_init 2

cstore_add_cluster 0 $cstore_server_host:1 $cstore_server_port:1
cstore_set_s3 0 $cstore_server_host:2 $cstore_server_port:2 region access_key secret_key \
	$cstore_server_tls:2 /abc/prefix/123

cstore_set_s3 1 $cstore_server_host:2 $cstore_server_port:2 region access_key secret_key \
	$cstore_server_tls:2 /abc/prefix/123

cstore_mock_s3 2 region access_key secret_key /abc/prefix/123

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 20

print "### WRITE"

set_var1 $sys_tmpdir "/test1.txt"
sys_write $var1 "test_ABC"

set_var2 $sys_tmpdir "/test2.txt"
sys_write $var2 "Test 22"

sleep_ms 20

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:0 4
equal $cstore_stat_roots:0 1
equal $cstore_stat_indexes:0 3
equal $cstore_stat_chunks:0 0

equal $cstore_entries:1 6
equal $cstore_stat_roots:1 1
equal $cstore_stat_indexes:1 3
equal $cstore_stat_chunks:1 2
equal $cstore_stat_http_200:1 8
equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0

equal $cstore_entries:2 4
equal $cstore_stat_roots:2 1
equal $cstore_stat_indexes:2 1
equal $cstore_stat_chunks:2 2
equal $cstore_stat_http_200:2 10
equal $cstore_stat_http_400:2 0
equal $cstore_stat_http_500:2 0

print "### READ"

cstore_clear 0
equal $cstore_entries:0 0

fs_test_release_all_wait

sleep_ms 10

sys_cat $var1 "test_ABC"
sys_cat $var2 "Test 22"

equal $cstore_stat_http_200:1 12
equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0

equal $cstore_stat_http_200:2 10
equal $cstore_stat_http_400:2 0
equal $cstore_stat_http_500:2 0

sleep_ms 20

print "### UNLINK"

sys_unlink $var2

sleep_ms 20

print "### CLEANUP"

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:2 3
equal $cstore_stat_roots:2 1
equal $cstore_stat_indexes:2 1
equal $cstore_stat_chunks:2 1

equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0
equal $cstore_stat_http_400:2 0
equal $cstore_stat_http_500:2 0

fs_test_release_all_wait 1

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
