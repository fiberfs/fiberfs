fiber_test "Rename file multiple times"

# Config
config_add FUSE_WRITEBACK_CACHE false
config_add CSTORE_ASYNC_WRITE false
config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

# Local, cluster, and S3
cstore_init 0
cstore_init 1
cstore_init 2

# Cstore S3 config
cstore_set_s3 0 $cstore_server_host:2 $cstore_server_port:2 region access_key secret_key
cstore_set_s3 1 $cstore_server_host:2 $cstore_server_port:2 region access_key secret_key
cstore_mock_s3 2 region access_key secret_key

# Cstore cluster config
cstore_add_cluster 0 $cstore_server_host:1 $cstore_server_port:1
cstore_add_cluster 0 $cstore_server_host:0 $cstore_server_port:0

# Mount
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### mkdir"

set dir $sys_tmpdir "/subdir_123"

sys_mkdir $dir

sleep_ms 20

print "### Write file_orig"

set file $dir "/somefile.123"

sys_write $file "some data"

sys_ls $sys_tmpdir "..:dir .:dir subdir_123:dir"
sys_ls $dir "..:dir .:dir somefile.123:file"

sleep_ms 20

print "### Rename to new"

set file_new $dir "/somefile.new"

sys_rename $file $file_new

sleep_ms 20

print "### Verify"

sys_ls $dir "..:dir .:dir somefile.new:file"

sys_cat $file_new "some data"

sleep_ms 20

print "### Verify (index)"

fs_test_release_all_wait

sys_ls $dir "..:dir .:dir somefile.new:file"

sys_cat $file_new "some data"

sleep_ms 20

print "### Append"

sys_append $file_new " more"

sys_cat $file_new "some data more"

sleep_ms 20

print "### Verify (index 2)"

fs_test_release_all_wait

sys_ls $dir "..:dir .:dir somefile.new:file"

sys_cat $file_new "some data more"

sleep_ms 20

print "### Rename again to FINAL"

set file2 $dir "/somefile.FINAL"

sys_rename $file_new $file2

sys_ls $dir "..:dir .:dir somefile.FINAL:file"

sleep_ms 20

sys_append $file2 " AGAIN"

sys_cat $file2 "some data more AGAIN"

sleep_ms 20

print "### Verify (index 3)"

fs_test_release_all_wait
cstore_clear 0
cstore_clear 1

sleep_ms 20

sys_ls $dir "..:dir .:dir somefile.FINAL:file"

sys_cat $file2 "some data more AGAIN"

sleep_ms 20

# Cleanup

print "### CLEANUP"

fs_test_release_all_wait 1

sleep_ms 20
fs_test_stats
fs_test_debug

cstore_debug 0
cstore_debug 1
cstore_debug 2

equal $cstore_stat_roots:2 2
equal $cstore_stat_indexes:2 2
equal $cstore_stat_chunks:2 3

equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0
equal $cstore_stat_http_400:2 0
equal $cstore_stat_http_500:2 0

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
