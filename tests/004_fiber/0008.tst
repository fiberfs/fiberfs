fiber_test "Holding onto an old inode"

skip_if_valgrind

# Init

sys_mkdir_tmp

fs_test_fuse_mount $sys_tmpdir

fs_test_fuse_init_root

# Load inodes

set_var1 $sys_tmpdir "/fiber_dir01/fiber_dir14"
sys_ls $var1

# Save old inode

_fs_test_take_dir $var1

# Expire cache

sleep_ms 1000

fs_test_release_root 0

# New operations

sys_ls $var1

# Cleanup

sleep_ms 100

fs_test_stats
fs_test_debug

_fs_test_release_dir
fs_test_release_root

sleep_ms 100

fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_files 4

fuse_test_unmount
