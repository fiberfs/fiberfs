fiber_test "Read only mount test"

# Init

config_add READ_ONLY true

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

sys_ls $sys_tmpdir "..:dir .:dir"

set file $sys_tmpdir "/test.txt"
open_write_error $file

# Cleanup

fs_test_release_all_wait 1

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
