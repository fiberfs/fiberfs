fiber_test "mkdir op test"

set_timeout_sec 20

config_add LOG_ALWAYS_FLUSH 1
config_add LOG_SHOW_DEBUG true

# Mount
sys_mkdir_tmp
mkdir_op_test_mount $sys_tmpdir

equal $fs_test_stat_directories 1

# mkdir success
set dir1 $sys_tmpdir "/test_start"
sys_mkdir $dir1
sleep_ms 10

equal $fs_test_stat_directories 2

# mkdir again, exists
mkdir_test_fail $dir1
sleep_ms 10

equal $fs_test_stat_directories 2

# Simulate a remote mkdir
set dir2 "test_remote_conflict"
mkdir_test_remote $dir2
sleep_ms 10

# Attempt local mkdir, exists
set dir3 $sys_tmpdir "/" $dir2
mkdir_test_fail $dir3
sleep_ms 10

equal $fs_test_stat_directories 2

# Simulate a remote file conflict
set dir2 "test_remote_file_conflict"
mkdir_test_remote_file $dir2
sleep_ms 10

# Attempt local mkdir, exists (directory exists in dindex only)
set dir3 $sys_tmpdir "/" $dir2
mkdir_test_fail $dir3
sleep_ms 10

equal $fs_test_stat_directories 3

# mkdir with a flush failure (directory exists in the dindex only)
set dir4 $sys_tmpdir "/test_flush_error"
mkdir_test_fail $dir4
sleep_ms 10

equal $fs_test_stat_directories 4

# mkdir and force sync
set dir5 $sys_tmpdir "/test_sync"
sys_mkdir $dir5
sleep_ms 10

equal $fs_test_stat_directories 5

# Cleanup

fs_test_release_all_wait 1

sleep_ms 10

fs_test_stats
fs_test_debug
cstore_debug

equal $cstore_stat_roots:0 4
equal $cstore_stat_indexes:0 4

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
