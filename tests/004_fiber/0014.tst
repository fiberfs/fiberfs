fiber_test "Reading inode while issuing new inode"

# Init

skip_if_valgrind

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir
fs_test_fuse_init_root

# Do operations

print "### TEST 1 (read and hold)"

set_var1 $sys_tmpdir "/fiber_zero1"
sys_stat_size $var1 500
sys_cat_md5 $var1 49a47e24ec21818ece7bccb86e9ad880

sleep_ms 100
fs_test_stats
fs_test_debug

_fs_test_take_file $var1 

# Drop and expire everything and get fresh inodes

sleep_ms 100
fs_test_stats
fs_test_debug

# One directory and one inode (and root inode)
equal $fs_test_stat_directories 1
equal $fs_test_stat_directories_dindex 1
equal $fs_test_stat_files_inodes 2

print "### TEST 2 (directory expired, new inodes)"

fs_test_release_root 0

sleep_ms 100
fs_test_stats
fs_test_debug

# Single saved inode
equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_files 2
equal $fs_test_stat_files_inodes 2

sys_stat_size $var1 500
sys_cat_md5 $var1 49a47e24ec21818ece7bccb86e9ad880

# Cleanup

sleep_ms 100
fs_test_stats
fs_test_debug

# Saved inode and new inode
equal $fs_test_stat_directories 1
equal $fs_test_stat_directories_dindex 1
equal $fs_test_stat_files_inodes 3

# The stale inode is forgotten after release
_fs_test_release_file
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
