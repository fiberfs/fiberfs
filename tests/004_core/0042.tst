fiber_test "chmod"

# Init
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### CREATE"

set_var1 $sys_tmpdir "/afile"
sys_write $var1 ""

sleep_ms 20

print "### CHMOD"

sys_chmod $var1 444

# File = 32768
# 0444 =   292
sys_stat_mode $var1 33060

# Read from index

fs_test_release_all_wait

print "### LOAD INDEX"

equal $fs_test_stat_index_loads 0

sys_stat_mode $var1 33060

equal $fs_test_stat_index_loads 1

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
