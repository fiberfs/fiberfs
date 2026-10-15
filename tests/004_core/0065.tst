fiber_test "Write twice"

# Init

config_add FUSE_WRITEBACK_CACHE false

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

set file $sys_tmpdir "/file.ini"
sys_write $file "write 1" " and two"

cstore_wait 0
equal $cstore_stat_chunks:0 1
equal $cstore_stat_chunks_fullfile:0 1

sys_write $file "second time" " here"

fs_test_release_all_wait

sys_cat $file "second time here"

# Cleanup

sleep_ms 10
cstore_debug
fs_test_stats
fs_test_debug

fs_test_release_all_wait 1

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

equal $cstore_stat_roots:0 1
equal $cstore_stat_indexes:0 1
equal $cstore_stat_chunks:0 1
equal $cstore_stat_chunks_fullfile:0 0

fuse_test_unmount
