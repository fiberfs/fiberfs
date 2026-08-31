fiber_test "Empty files"

# Init
config_add FUSE_WRITEBACK_CACHE true

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### CREATE EMPTY"

equal $fs_test_stat_flushes 0

set file $sys_tmpdir "/somefile"
sys_write_seek $file 0 ""

greater_equal $fs_test_stat_flushes 1

sleep_ms 50

fs_test_release_all_wait
equal $fs_test_stat_files_inodes 1

print "### VERIFY"

sys_stat_size $file 0
sys_cat $file ""

print "### WRITE"

sys_write $file "123"

greater_equal $fs_test_stat_flushes 2

sleep_ms 50

fs_test_release_all_wait
equal $fs_test_stat_files_inodes 1

print "### VERIFY 2"

sys_stat_size $file 3
sys_cat $file "123"

equal $cstore_stat_chunks:0 1

sleep_ms 20

print "### WRITE NOTHING"

sys_write_seek $file 0 ""

sleep_ms 20

greater_equal $fs_test_stat_flushes 2

print "### WRITE TRUNCATE"

sys_write $file ""

greater_equal $fs_test_stat_flushes 3

sleep_ms 50

fs_test_release_all_wait
equal $fs_test_stat_files_inodes 1

print "### VERIFY 3"

sys_stat_size $file 0
sys_cat $file ""

# Cleanup

print "### CLEANUP"

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
equal $cstore_stat_chunks:0 0

fuse_test_unmount
