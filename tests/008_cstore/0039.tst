fiber_test "cstore s3 import errors"

# config

config_add FUSE_WRITEBACK_CACHE false
config_add LOG_SIZE 200000

# Init cstores (0: local 1: s3)

cstore_init 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 1

cstore_set_s3 0 $cstore_server_host:1 $cstore_server_port:1 region access_key somesecret
cstore_mock_s3 1 region access_key somesecret

print "### MOUNT"

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 10

print "### SETUP"

set filename "test.file"
set filepath $sys_tmpdir "/" $filename

sys_write $filepath "version one"

equal $cstore_stat_chunks_fullfile:1 1

sys_write $filepath "version two"

equal $cstore_stat_chunks_fullfile:1 0

print "### UPLOAD"

cstore_s3_upload $filename 2370

equal $cstore_stat_chunks_fullfile:1 1
equal $cstore_stat_chunks:1 2

sleep_ms 50

print "### VERIFY 1 (CSTORE)"

fs_test_release_all_wait
sleep_ms 20

sys_ls $sys_tmpdir "..:dir .:dir test.file:file"
sys_cat $filepath "version two"

sleep_ms 50

print "### IMPORT"

iocmd_import_error $filepath
iocmd_import $filepath 1

equal $cstore_stat_chunks_fullfile:1 1
equal $cstore_stat_chunks:1 1

print "### VERIFY 2 (CSTORE)"

fs_test_release_all_wait
sleep_ms 20

sys_ls $sys_tmpdir "..:dir .:dir test.file:file"
sys_stat_size $filepath 2370
sys_cat_md5 $filepath $cstore_s3_md5

sleep_ms 50

print "### DELETE"

sys_unlink $filepath

print "### VERIFY 3 (CSTORE)"

fs_test_release_all_wait
sleep_ms 20

sys_ls $sys_tmpdir "..:dir .:dir"

equal $cstore_stat_chunks_fullfile:1 1
equal $cstore_stat_chunks:1 1

sleep_ms 100

print "### SUBDIR FILE2"

set file2 "dirx/test2_file"
set path2 $sys_tmpdir "/" $file2
set dirpath $sys_tmpdir "/dirx"

cstore_s3_upload $file2 781

equal $cstore_stat_chunks_fullfile:1 2

sleep_ms 20

print "### IMPORT FILE2"

iocmd_import_error $path2

sys_mkdir $dirpath

iocmd_import $path2

sleep_ms 100
print "### FILE DIR FILE3"

set file3 "dirZ/test3_file"
set path3 $sys_tmpdir "/" $file3
set dirpath3 $sys_tmpdir "/dirZ"

sys_write $dirpath3 ""

iocmd_import_error $path3

print "### DONE"

fs_test_release_all_wait 1
sleep_ms 10

fs_test_stats
cstore_wait 0
cstore_debug 1

equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0

equal $cstore_stat_chunks_fullfile:1 2
equal $cstore_stat_chunks:1 2
equal $cstore_stat_indexes:1 2
equal $cstore_stat_roots:1 2

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
