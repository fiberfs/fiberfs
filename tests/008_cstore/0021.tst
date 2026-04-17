fiber_test "cstore large write with cluster"

skip_if $is_valgrind

config_add LOG_SIZE 1000000
#config_add LOG_ALWAYS_FLUSH true
config_add ASYNC_WRITE false

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

# This is the local FiberFS
cstore_init 0

# Two remote FiberFS peers
cstore_init 1
cstore_init 2

# S3
cstore_init 3
cstore_mock_s3 3 region access_key secret_key

# Set the S3 origin for all cstores
cstore_set_s3 0 $cstore_server_host:3 $cstore_server_port:3 region access_key secret_key
cstore_set_s3 1 $cstore_server_host:3 $cstore_server_port:3 region access_key secret_key
cstore_set_s3 2 $cstore_server_host:3 $cstore_server_port:3 region access_key secret_key

# Build the cluster on the local
cstore_add_cluster 0 $cstore_server_host:0 $cstore_server_port:0
cstore_add_cluster 0 $cstore_server_host:1 $cstore_server_port:1
cstore_add_cluster 0 $cstore_server_host:2 $cstore_server_port:2

# Start the test

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

print "### WRITE"

set_var1 $sys_tmpdir "/test_big1.txt"
sys_write_random_md5 $var1 2000000

fs_test_release_all

print "### READ"

sys_cat_md5 $var1 $md5_write

cstore_debug
cstore_debug 1
cstore_debug 2
cstore_debug 3

equal $cstore_entries:3 12
equal $cstore_stat_chunks:3 10
equal $cstore_stat_indexes:3 1
equal $cstore_stat_roots:3 1

greater_equal $cstore_stat_chunk_read_bytes:0 2000000
equal $cstore_stat_chunk_write_bytes:3 2000000

fs_test_release_all 1

sleep_ms 200
fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
