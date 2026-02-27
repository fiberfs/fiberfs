fiber_test "RW test small buffer"

# Init

config_add DEBUG_FS_WBUFFER_ALLOC_SIZE 3
config_add LOG_ALWAYS_FLUSH 1

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 1 333 999999999 55555 1 666666

equal $fs_test_stat_write_bytes 25

sys_cat $var1 "1333999999999555551666666"

equal $fs_test_stat_read_bytes 25

# Cleanup

fs_test_release_all 1

sleep_ms 200
fs_test_stats
fs_test_debug

cstore_debug

equal $cstore_stat_chunk_write_bytes 25
equal $cstore_stat_chunk_read_bytes 25
greater_than $cstore_stat_index_write_bytes 0
greater_than $cstore_stat_root_write_bytes 0

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
