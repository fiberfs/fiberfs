fiber_test "Empty files"

# Init
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### CREATE EMPTY"

equal $fs_test_stat_flushes 0

set_var1 $sys_tmpdir "/somefile"
sys_write_seek $var1 0 ""

equal $fs_test_stat_flushes 1

fs_test_release_all
sleep_ms 200

print "### VERIFY"

sys_stat_size $var1 0
sys_cat $var1 ""

print "### WRITE"

sys_write $var1 "123"

equal $fs_test_stat_flushes 2

fs_test_release_all
sleep_ms 200

print "### VERIFY 2"

sys_stat_size $var1 3
sys_cat $var1 "123"

equal $cstore_stat_chunks:0 1

sleep_ms 20

print "### WRITE NOTHING"

sys_write_seek $var1 0 ""

sleep_ms 20

equal $fs_test_stat_flushes 2

print "### WRITE TRUNCATE"

sys_write $var1 ""

equal $fs_test_stat_flushes 3

fs_test_release_all
sleep_ms 200

print "### VERIFY 3"

sys_stat_size $var1 0
sys_cat $var1 ""

# Cleanup

print "### CLEANUP"

fs_test_release_all 1

sleep_ms 200
fs_test_stats
fs_test_debug

cstore_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0
equal $cstore_stat_chunks:0 0

fuse_test_unmount
