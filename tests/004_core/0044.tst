fiber_test "O_EXCL"

# Init
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### CREATE 1"

set_var1 $sys_tmpdir "/1file"
sys_write_exclusive $var1 "one"

sleep_ms 20

print "### CREATE 2 (remote exists)"

set_var2 "2file"
mkdir_test_remote_file $var2

set_var3 $sys_tmpdir "/" $var2
sys_open_exclusive_error $var3

sleep_ms 20

print "### CREATE 3 (local exists)"

sys_open_exclusive_error $var3

sleep_ms 20

print "### CREATE 4 (local exists no cache)"

fs_test_release_all_wait

sleep_ms 20

sys_open_exclusive_error $var3

# Cleanup

print "### CLEANUP"

fs_test_release_all_wait 1

sleep_ms 20
fs_test_stats
fs_test_debug
cstore_debug

equal $cstore_stat_chunks:0 1
equal $cstore_stat_indexes:0 1
equal $cstore_stat_roots:0 1

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
