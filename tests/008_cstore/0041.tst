fiber_test "cstore s3 merge"

# TODO fullfile needs to exist in cache for merge to work

# Init cstores (0: local 1: s3)

cstore_init 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 1

cstore_set_s3 0 $cstore_server_host:1 $cstore_server_port:1 region access_key sEcrEt_kEy \
	$cstore_server_tls:1 prefixZzZ
cstore_mock_s3 1 region access_key sEcrEt_kEy prefixZzZ

print "### MOUNT"

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 10

print "### WRITE"

set file $sys_tmpdir "/some_vi.doc"
sys_write $file "Test1Test2Test3"
sys_append $file " Test4Test5"

equal $cstore_stat_chunks:1 2
equal $cstore_stat_chunks_fullfile:1 1

sleep_ms 20

print "### MERGE"

iocmd_merge $file

equal $cstore_stat_chunks:1 1
equal $cstore_stat_chunks_fullfile:1 1

print "### VERIFY (MEMORY)"

sys_ls $sys_tmpdir "..:dir .:dir some_vi.doc:file"
sys_stat_size $file 26
sys_cat $file "Test1Test2Test3 Test4Test5"

print "### VERIFY (CSTORE)"

fs_test_release_all_wait
sleep_ms 20

sys_ls $sys_tmpdir "..:dir .:dir some_vi.doc:file"
sys_stat_size $file 26
sys_cat $file "Test1Test2Test3 Test4Test5"

print "### DONE"

fs_test_release_all_wait 1
sleep_ms 10

fs_test_stats
cstore_wait 0
cstore_debug 1

equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0

equal $cstore_stat_chunks:1 1
equal $cstore_stat_chunks_fullfile:1 1

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
