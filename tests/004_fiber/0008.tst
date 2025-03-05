fiber_test "Holding onto an old inode"

# Init

skip_if_valgrind

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir
fs_test_fuse_init_root

# Load inodes

print "### TEST 1 (load inode)"

set_var1 $sys_tmpdir "/fiber_dir01/fiber_dir14"
sys_ls $var1

sleep_ms 100
fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 3
equal $fs_test_stat_directories_dindex 3
equal $fs_test_stat_files_inodes 3

# Save old inode

print "### TEST 2 (save inode)"

_fs_test_take_dir $var1

# Expire cache

print "### TEST 3 (expire cache)"

sleep_ms 100
fs_test_stats
fs_test_debug

fs_test_release_root 0

sleep_ms 100
fs_test_stats
fs_test_debug

# We internally hold the directory and linux holds all inodes
equal $fs_test_stat_directories 1
equal $fs_test_stat_directories_dindex 1
equal $fs_test_stat_files_inodes 3

# New operations

print "### TEST 4 (new operations)"

sys_ls $var1

# Cleanup

print "### TEST 5 (cleanup and release)"

sleep_ms 100
fs_test_stats
fs_test_debug

# 3 directories and 1 internal non-dindex
# 5 inodes (old + new)
equal $fs_test_stat_directories 4
equal $fs_test_stat_directories_dindex 3
equal $fs_test_stat_files_inodes 5

_fs_test_release_dir
fs_test_release_root

sleep_ms 100
fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
