fiber_test "RW append and remote writes"

# Init

config_add FUSE_WRITEBACK_CACHE false

set_timeout_sec 20
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### LOCAL APPEND 1"

set filename "append_global.txt"
set file $sys_tmpdir "/" $filename
sys_append $file "wr1"

print "### LOCAL APPEND 2"

sys_append $file "wr2" "wr3"

print "### READ (memory)"

sys_stat_size $file 9
sys_cat $file "wr1wr2wr3"

print "### REMOTE APPEND"

remote_append $filename "wr4" "wr5"

print "### LOCAL APPEND 3"

sys_append $file "wr6" "wr7"

print "### READ (memory)"

sys_stat_size $file 21
sys_cat $file "wr1wr2wr3wr4wr5wr6wr7"

print "### READ (cstore)"

fs_test_release_all_wait
sleep_ms 10

sys_stat_size $file 21
sys_cat $file "wr1wr2wr3wr4wr5wr6wr7"

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
equal $fs_test_stat_appends 5
equal $cstore_stat_chunks:0 7

fuse_test_unmount
