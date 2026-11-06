fiber_test "cstore s3 import connection errors"

# Config
config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

# Init cstores (0: local 1: s3)
cstore_init 0
cstore_init 1

cstore_epool_close 0
cstore_epool_close 1

cstore_set_s3 0 $cstore_server_host:1 $cstore_server_port:1 region access_key sEcrEt_kEy \
	$cstore_server_tls:1 "prefixA1C/ ???/"
cstore_mock_s3 1 region access_key sEcrEt_kEy "prefixA1C/ ???/"

print "### MOUNT"

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 10

print "### UPLOAD"

set filename1 "abcfile1"
set filepath1 $sys_tmpdir "/" $filename1
set filename2 "abcfile \"?\""
set filepath2 $sys_tmpdir "/" $filename2
set filename3 "abcfile 333"
set filepath3 $sys_tmpdir "/" $filename3

cstore_s3_upload $filename1 1234
cstore_s3_upload $filename2 5678
cstore_s3_upload $filename3 9909

equal $cstore_stat_chunks_fullfile:1 3

print "### IMPORT"

iocmd_import $filepath1
iocmd_import $filepath2
iocmd_import $filepath3

print "### VERIFY (MEMORY)"

sys_ls $sys_tmpdir "..:dir .:dir abcfile \"?\":file abcfile 333:file abcfile1:file"
sys_stat_size $filepath1 1234
sys_stat_size $filepath2 5678
sys_stat_size $filepath3 9909
sys_cat_md5 $filepath3 $cstore_s3_md5

print "### VERIFY (CSTORE)"

fs_test_release_all_wait
sleep_ms 20

sys_ls $sys_tmpdir "..:dir .:dir abcfile \"?\":file abcfile 333:file abcfile1:file"
sys_stat_size $filepath1 1234
sys_stat_size $filepath2 5678
sys_stat_size $filepath3 9909
sys_cat_md5 $filepath3 $cstore_s3_md5

print "### DONE"

fs_test_release_all_wait 1
sleep_ms 10

fs_test_stats
cstore_wait 0
cstore_debug 1

equal $cstore_stat_http_400:0 0
equal $cstore_stat_http_500:0 0
equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
