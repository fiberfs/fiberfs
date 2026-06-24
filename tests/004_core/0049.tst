fiber_test "Write with O_SYNC"

# Init

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

set_var1 $sys_tmpdir "/test_file.log"
sys_write_sync $var1 "write 1" " and two"
sys_write_sync $var1 "again" " and again"

fs_test_release_all_wait

sys_cat $var1 "again and again"

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

equal $fs_test_stat_flushes 6
equal $fs_test_stat_flush_memory 0

equal $cstore_stat_chunk_write_bytes:0 30
equal $cstore_stat_chunk_read_bytes:0 15

equal $cstore_stat_roots:0 1
equal $cstore_stat_indexes:0 1
equal $cstore_stat_chunks:0 2
equal $cstore_stat_root_updates:0 7

fuse_test_unmount
