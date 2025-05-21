fiber_test "RW create and write again"

# Init

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir
fs_test_dentry_ttl_ms 0
fs_test_rw_buffer_size 3

# Operations

print "### CREATE"

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "123" "4" "567" "89012" "345" "6" "7890"

sleep_ms 100

print "### WRITE"

sys_write_seek $var1 0 "ABC" "DE" "FG"

print "### READ (memory)"

sys_cat $var1 "ABCDEFG8901234567890"

sleep_ms 100

print "### READ (dstore)"

fs_test_release_all
sleep_ms 100

sys_cat $var1 "ABCDEFG8901234567890"

# Cleanup

fs_test_release_all 1

sleep_ms 200
fs_test_stats
fs_test_debug

dstore_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
