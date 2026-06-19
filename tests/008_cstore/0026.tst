fiber_test "cstore and deleted S3 files"

config_add ROOT_FILE_TTL_SEC 0

cstore_init 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

# Peer
cstore_init 1
cstore_add_cluster 0 $cstore_server_host:1 $cstore_server_port:1

# S3
cstore_init 2
cstore_set_s3 0 $cstore_server_host:2 $cstore_server_port:2 region access_key secret_key
cstore_set_s3 1 $cstore_server_host:2 $cstore_server_port:2 region access_key secret_key
cstore_mock_s3 2 region access_key secret_key

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 10

print "### WRITE"

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "test_ABC"

sleep_ms 10

cstore_debug
cstore_debug 1
cstore_debug 2

equal $cstore_entries:0 3
equal $cstore_entries:1 4
equal $cstore_entries:2 3

print "### Delete S3 and READ"

cstore_clear 2
equal $cstore_entries:2 0
fs_test_release_all_wait

sleep_ms 250

sys_ls $sys_tmpdir "..:dir .:dir test.txt:file"
sys_cat $var1 "test_ABC"

sleep_ms 50

greater_equal $cstore_stat_http_400:2 1

print "### Delete cluster and READ"

cstore_clear 1
equal $cstore_entries:1 0
fs_test_release_all_wait

sleep_ms 250

sys_ls $sys_tmpdir "..:dir .:dir test.txt:file"

sleep_ms 50

greater_equal $cstore_stat_http_400:1 1

sleep_ms 30

sys_cat_error $var1

print "### DELETE cache and READ"

cstore_clear 0
equal $cstore_entries:0 0

sleep_ms 250

sys_ls $sys_tmpdir "..:dir .:dir test.txt:file"

print "### DELETE dindex and READ"

sleep_ms 50

fs_test_release_all_wait

sys_ls_error $sys_tmpdir

print "### CLEANUP"

fs_test_release_all_wait 1

sleep_ms 20
fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
