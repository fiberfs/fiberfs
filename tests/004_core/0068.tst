fiber_test "iocmd ping"

# Mount

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# PING PONG

iocmd_ping $sys_tmpdir

# Unmount

fs_test_release_all_wait 1

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
