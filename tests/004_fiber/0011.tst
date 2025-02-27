fiber_test "File reading"

# Init

sys_mkdir_tmp

fs_test_fuse_mount $sys_tmpdir

fs_test_fuse_init_root

# Do operations

set_var1 $sys_tmpdir "/fiber_03"
sys_stat_size $var1 0

set_var1 $sys_tmpdir "/fiber_dir01/fiber_12"
sys_stat_size $var1 2002

set_var1 $sys_tmpdir "/fiber_dir01/fiber_dir11/fiber_24"
sys_stat_size $var1 8008

# Cleanup

sleep_ms 100

fs_test_release_root

sleep_ms 100

fs_test_stats
fs_test_debug

#equal $fs_test_stat_directories 0
#equal $fs_test_stat_files 4

fuse_test_unmount
