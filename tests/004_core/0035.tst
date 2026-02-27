fiber_test "mkdir"

# Init

config_add LOG_ALWAYS_FLUSH 1

test_log_allow_debug
sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# mkdir

set_var1 $sys_tmpdir "/test1"
sys_mkdir $var1

sleep_ms 100

# release

fs_test_release_all
sleep_ms 100

# re-read

sys_ls $sys_tmpdir "..:dir .:dir test1:dir"

# Cleanup

fs_test_release_all 1

sleep_ms 200
fs_test_stats
fs_test_debug

cstore_debug

equal $cstore_stat_roots 2
equal $cstore_stat_indexes 2

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
