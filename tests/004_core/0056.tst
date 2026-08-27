fiber_test "Filename json chars test"

# Init

set_timeout_sec 20
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

set file $sys_tmpdir "/\"test\".txt"
sys_write $file "test quoted."

sleep_ms 10
fs_test_release_all_wait

sys_ls $sys_tmpdir '"test".txt:file ..:dir .:dir'
sys_cat $file "test quoted."

# Cleanup

sleep_ms 10
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

fuse_test_unmount
