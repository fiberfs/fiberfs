fiber_test "mkdir op test"

sys_mkdir_tmp
mkdir_op_test_mount $sys_tmpdir

equal $fs_test_stat_directories 1

set_var1 $sys_tmpdir "/test_start"
sys_mkdir $var1
sleep_ms 10

equal $fs_test_stat_directories 2

mkdir_test_fail $var1
sleep_ms 10

set_var2 "test_remote_conflict"
mkdir_test_remote $var2
sleep_ms 10

equal $fs_test_stat_directories 2

set_var3 $sys_tmpdir "/" $var2
mkdir_test_fail $var3
sleep_ms 10

equal $fs_test_stat_directories 2

set_var4 $sys_tmpdir "/test_flush_error"
mkdir_test_fail $var4
sleep_ms 10

equal $fs_test_stat_directories 3

set_var5 $sys_tmpdir "/test_sync"
sys_mkdir $var5
sleep_ms 10

equal $fs_test_stat_directories 4

# Cleanup

fs_test_release_all 1

sleep_ms 200

fs_test_stats
fs_test_debug
dstore_debug

equal $dstore_stat_roots 4
equal $dstore_stat_indexes 4

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
