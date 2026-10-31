fiber_test "cstore s3 merge errors"

# TODO fullfile needs to exist in cache for merge to work

# Config

config_add CSTORE_ASYNC_WRITE false
config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

# Init cstores (0: local 1: s3)

cstore_init 0
cstore_init 1

cstore_set_s3 0 $cstore_server_host:1 $cstore_server_port:1 region access_key sEcrEt_kEy \
	$cstore_server_tls:1 prefix_321/abc
cstore_mock_s3 1 region access_key sEcrEt_kEy prefix_321/abc

print "### MOUNT"

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

sleep_ms 10

print "### WRITE 1"

set dirname "directory_here"
set dirpath $sys_tmpdir "/" $dirname
set filename "directory_here/data.log"
set filepath $sys_tmpdir "/" $filename

sys_mkdir $dirpath

sys_write $filepath "line1"
sys_append $filepath "line2"

equal $cstore_stat_chunks:1 2
equal $cstore_stat_chunks_fullfile:1 1

print "### MERGE 1"

iocmd_merge $filepath

equal $cstore_stat_chunks:1 1
equal $cstore_stat_chunks_fullfile:1 1

print "### WRITE 2"

# Load the cache and wait for write
fs_test_release_all_wait
sleep_ms 20
sys_cat $filepath "line1line2"

sys_append $filepath "line3"

equal $cstore_stat_chunks:1 2
equal $cstore_stat_chunks_fullfile:1 1

iocmd_merge $filepath

equal $cstore_stat_chunks:1 1
equal $cstore_stat_chunks_fullfile:1 1

sys_append $filepath "line4"

# Load the cache and wait for write
fs_test_release_all_wait
sleep_ms 20
sys_cat $filepath "line1line2line3line4"

equal $cstore_stat_chunks:1 2
equal $cstore_stat_chunks_fullfile:1 1

iocmd_merge $filepath

equal $cstore_stat_chunks:1 1
equal $cstore_stat_chunks_fullfile:1 1

print "### WRITE 3 (mark external)"

sys_append $filepath "line5"

equal $cstore_stat_chunks:1 2
equal $cstore_stat_chunks_fullfile:1 1

sys_cat $filepath "line1line2line3line4line5"

iocmd_import $filepath 1

equal $cstore_stat_chunks:1 1
equal $cstore_stat_chunks_fullfile:1 1

print "### MERGE FAILURE (external)"

sys_append $filepath "line6"

equal $cstore_stat_chunks:1 2
equal $cstore_stat_chunks_fullfile:1 1

iocmd_merge_error $filepath

print "### VERIFY (CSTORE)"

fs_test_release_all_wait
sleep_ms 20

sys_ls $dirpath "..:dir .:dir data.log:file"
sys_stat_size $filepath 25
sys_cat $filepath "line1line2line3line4line6"

print "### DONE"

fs_test_release_all_wait 1
sleep_ms 10

fs_test_stats
cstore_wait 0
cstore_debug 1

equal $cstore_stat_http_400:1 0
equal $cstore_stat_http_500:1 0

equal $cstore_stat_chunks:1 2
equal $cstore_stat_chunks_fullfile:1 1

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
