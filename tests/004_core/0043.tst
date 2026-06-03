fiber_test "Resizing"

# Init
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### Extend"

set_var1 $sys_tmpdir "/somefile"
sys_truncate $var1 16

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
