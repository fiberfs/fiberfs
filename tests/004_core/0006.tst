fiber_test "Fuse and fs"

# Init

set_timeout_sec 20

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir
fs_test_fuse_init_root

# Do a bunch of operations

print "### TEST 1"

sys_ls $sys_tmpdir

set dir1 $sys_tmpdir "/fiber_dir02"
sys_ls $dir1

set dir2 $dir1 "/fiber_dir13"
sys_ls $dir2

# Expire cache

print "### TEST 2 (release root)"

sleep_ms 10
fs_test_stats
fs_test_debug

fs_test_release_all_wait

fs_test_stats
fs_test_debug

# New operations

print "### TEST 3 (more operations)"

sys_ls $sys_tmpdir
sys_ls $dir1
sys_ls $dir2

# Cleanup

sleep_ms 10
fs_test_stats
fs_test_debug

fs_test_release_all_wait 1

sleep_ms 10
fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
