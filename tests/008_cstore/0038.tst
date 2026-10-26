fiber_test "cstore s3 import with lots of chunks"

# Variables

config_add DEBUG_FS_IMPORT_CHUNK_SIZE 8

# Init cstores (0: local 1: s3)

cstore_init 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 1

cstore_set_s3 0 $cstore_server_host:1 $cstore_server_port:1 region access_key sEcrEt_kEy \
	$cstore_server_tls:1 prefixA1C
cstore_mock_s3 1 region access_key sEcrEt_kEy prefixA1C

print "### MOUNT"

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 10

print "### UPLOAD"

set filename "external.log"
set filepath $sys_tmpdir "/" $filename

cstore_s3_upload $filename 6597

equal $cstore_stat_chunks_fullfile:1 1

print "### IMPORT"

iocmd_import $filepath

print "### VERIFY (MEMORY)"

sys_ls $sys_tmpdir "..:dir .:dir external.log:file"
sys_stat_size $filepath 6597
sys_cat_md5 $filepath $cstore_s3_md5

print "### VERIFY (CSTORE)"

fs_test_release_all_wait
sleep_ms 20

sys_ls $sys_tmpdir "..:dir .:dir external.log:file"
sys_stat_size $filepath 6597
sys_cat_md5 $filepath $cstore_s3_md5

print "### DONE"

fs_test_release_all_wait 1
sleep_ms 10

fs_test_stats
cstore_wait 0
cstore_debug 1

equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0

equal $cstore_stat_chunk_write_bytes:1 6597
equal $cstore_stat_chunk_read_bytes:1 6597

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
