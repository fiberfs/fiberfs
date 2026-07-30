fiber_test "RW append with writeback caching"

# Init

config_add FUSE_WRITEBACK_CACHE true

set_timeout_sec 20
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### APPEND 1"

set file $sys_tmpdir "/append.txt"
sys_append $file "ONE"

sleep_ms 100

print "### APPEND 2"

sys_append $file "T" "W" "OoO"
sys_append $file "THREE"

print "### READ (memory)"

sys_cat $file "ONETWOoOTHREE"

sleep_ms 100

print "### READ (cstore)"

fs_test_release_all_wait
sleep_ms 10

sys_cat $file "ONETWOoOTHREE"

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
equal $fs_test_stat_appends 0
greater_equal $fs_test_stat_flushes 3
equal $fs_test_stat_flush_memory 1
equal $cstore_stat_chunks:0 1

fuse_test_unmount
