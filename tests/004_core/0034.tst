fiber_test "RW append"

# Init

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir
fs_test_dentry_ttl_ms 0

# Operations

print "### APPEND 1"

set_var1 $sys_tmpdir "/append.txt"
sys_append $var1 "ONE"

sleep_ms 100

print "### APPEND 2"

sys_append $var1 "T" "W" "OoO"
sys_append $var1 "THREE"

print "### READ (memory)"

sys_cat $var1 "ONETWOoOTHREE"

sleep_ms 100

#print "### READ (dstore)"

#fs_test_release_all
#sleep_ms 100

#sys_cat $var1 "ONETWOTHREE"

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
equal $fs_test_stat_store_chunks 5

fuse_test_unmount
