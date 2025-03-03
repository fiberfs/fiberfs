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

_fs_test_take_file $var1 

# Drop and expire everything and get fresh inodes

sleep_ms 1000

print "### TEST 2 (directory expired, new inodes)"

fs_test_release_root 0

fs_test_stats
fs_test_debug

sys_stat_size $var1 500
sys_cat_md5 $var1 49a47e24ec21818ece7bccb86e9ad880

# Cleanup

sleep_ms 100

fs_test_stats
fs_test_debug

_fs_test_release_file
fs_test_release_root

sleep_ms 200

fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_files 1

fuse_test_unmount
