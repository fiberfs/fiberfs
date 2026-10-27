fiber_test "cstore s3 import with lots of chunks and cstores"

# Variables

config_add DEBUG_FS_IMPORT_CHUNK_SIZE 2
config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0
config_add LOG_SIZE 300000

# Init cstores (0: local 1: cluster 2: cdn 3: s3)

cstore_init 0
cstore_init 1
cstore_init 2
cstore_init 3

# cstore s3
cstore_set_s3 0 $cstore_server_host:3 $cstore_server_port:3 reg ac k3y
cstore_set_s3 1 $cstore_server_host:3 $cstore_server_port:3 reg ac k3y
cstore_set_s3 2 $cstore_server_host:3 $cstore_server_port:3 reg ac k3y
cstore_mock_s3 3 reg ac k3y

# cstore cluster
cstore_add_cluster 0 $cstore_server_host:0 $cstore_server_port:0
cstore_add_cluster 0 $cstore_server_host:1 $cstore_server_port:1

# cstore cdn
cstore_add_cdn 0 $cstore_server_host:2 $cstore_server_port:2
cstore_add_cdn 1 $cstore_server_host:2 $cstore_server_port:2

print "### MOUNT"

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 10

print "### UPLOAD"

set filename "bigfile.bin"
set filepath $sys_tmpdir "/" $filename

cstore_s3_upload $filename 234567

equal $cstore_stat_chunks_fullfile:3 1

print "### IMPORT"

iocmd_import $filepath

print "### VERIFY (MEMORY)"

sys_ls $sys_tmpdir "..:dir .:dir bigfile.bin:file"
sys_stat_size $filepath 234567
sys_cat_md5 $filepath $cstore_s3_md5

print "### VERIFY (CSTORE)"

fs_test_release_all_wait
sleep_ms 20

sys_ls $sys_tmpdir "..:dir .:dir bigfile.bin:file"
sys_stat_size $filepath 234567
sys_cat_md5 $filepath $cstore_s3_md5

print "### DELETE"

sys_unlink $filepath

print "### VERIFY 2 (CSTORE)"

fs_test_release_all_wait
sleep_ms 20

sys_ls $sys_tmpdir "..:dir .:dir"

equal $cstore_stat_chunks_fullfile:3 1

print "### DONE"

fs_test_release_all_wait 1
sleep_ms 10

fs_test_stats
cstore_debug 0
cstore_debug 1
cstore_debug 2
cstore_debug 3

equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0
equal $cstore_stat_http_400:2 0
equal $cstore_stat_http_500:2 0
equal $cstore_stat_http_400:3 0
equal $cstore_stat_http_500:3 0

equal $cstore_stat_chunk_write_bytes:3 234567
equal $cstore_stat_chunk_read_bytes:3 234567

equal $cstore_stat_chunks_fullfile:3 1
equal $cstore_stat_chunks:3 1
equal $cstore_stat_roots:3 1
equal $cstore_stat_indexes:3 1

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
