fiber_test "rmdir"

# Init
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### mkdirs and write"

set_var1 $sys_tmpdir "/dir1"
sys_mkdir $var1

set_var2 $var1 "/sub_directory"
sys_mkdir $var2

set_var3 $var2 "/fav_abc"
sys_write $var3 "Hello fav abc."

sleep_ms 20

equal $cstore_stat_roots:0 3
equal $cstore_stat_indexes:0 3
equal $cstore_stat_chunks:0 1

# rmdir

print "### RMDIRs"

fs_test_release_all_wait

sys_rmdir_error $var2

sleep_ms 20

sys_unlink $var3

sleep_ms 20

sys_rmdir $var2

sleep_ms 20

equal $cstore_stat_roots:0 2
equal $cstore_stat_indexes:0 2
equal $cstore_stat_chunks:0 0

sys_rmdir $var1

sleep_ms 20

equal $cstore_stat_roots:0 1
equal $cstore_stat_indexes:0 1
equal $cstore_stat_chunks:0 0

print "### Verify"

fs_test_release_all_wait

sys_ls $sys_tmpdir "..:dir .:dir"

# Cleanup

print "### CLEANUP"

fs_test_release_all_wait 1

sleep_ms 20
fs_test_stats
fs_test_debug
cstore_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
