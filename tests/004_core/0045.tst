fiber_test "Unlink file"

# Init
config_add DEBUG_FS_WBUFFER_ALLOC_SIZE 3

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### Write"

set_var1 $sys_tmpdir "/Zfile"
sys_write $var1 "ABC" "123" "ZZZ"

print "### Unlink"

sleep_ms 20

equal $cstore_stat_chunks:0 3

sys_unlink $var1

equal $cstore_stat_chunks:0 0

sleep_ms 20

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
