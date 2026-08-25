fiber_test "RW create and truncate"

# Init

config_add DEBUG_FS_WBUFFER_ALLOC_SIZE 3
config_add LOG_SHOW_DEBUG true
config_add FUSE_WRITEBACK_CACHE false

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### CREATE"

set file $sys_tmpdir "/test.txt"
sys_write $file "123" "4" "567" "89012" "345" "6" "7890"

cstore_debug

equal $cstore_stat_chunks:0 7

sleep_ms 10

print "### TRUNCATE"

sys_write $file "ABC" "DE" "FG"

print "### READ (memory)"

sys_cat $file "ABCDEFG"

sleep_ms 10

print "### READ (cstore)"

fs_test_release_all_wait
sleep_ms 10

sys_cat $file "ABCDEFG"

# Cleanup

fs_test_release_all_wait 1

sleep_ms 10
fs_test_stats
fs_test_debug

cstore_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0
equal $cstore_stat_chunks:0 3

test_log_debug

fuse_test_unmount
