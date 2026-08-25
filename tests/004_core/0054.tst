fiber_test "RW test with writeback and setattr invalidation"

# Init

config_add FUSE_WRITEBACK_CACHE true
config_add ATTR_TIME_CHANGE_IGNORE 0 

set_timeout_sec 20
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

sys_ls $sys_tmpdir "..:dir .:dir"

set file $sys_tmpdir "/test.txt"
sys_write $file "test1" "test2" "test3"

greater_equal $fs_test_stat_write_bytes 15

sys_ls $sys_tmpdir "..:dir .:dir test.txt:file"
sys_stat_size $file 15
sys_cat $file "test1test2test3"

equal $fs_test_stat_read_bytes 15

# Cleanup

sleep_ms 10
fs_test_stats
fs_test_debug

fs_test_release_all_wait 1

sleep_ms 10
fs_test_stats
fs_test_debug

cstore_debug

equal $cstore_stat_chunk_write_bytes:0 15
equal $cstore_stat_chunk_read_bytes:0 15
equal $cstore_stat_roots:0 1
equal $cstore_stat_indexes:0 1
equal $cstore_stat_chunks:0 1

equal $cstore_stat_root_updates:0 3

equal $fs_test_stat_flushes 2
equal $fs_test_stat_flush_memory 1

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
