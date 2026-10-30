fiber_test "fiberfs_cmd --ping"

# Mount

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# PING PONG

shell ../src/fiberfs_cmd -p $sys_tmpdir >/dev/null 2>&1

# gcov

shell ../src/fiberfs_cmd >/dev/null 2>&1 || true
shell ../src/fiberfs_cmd -ifp >/dev/null 2>&1 || true
shell ../src/fiberfs_cmd -p >/dev/null 2>&1 || true
shell ../src/fiberfs_cmd -pf >/dev/null 2>&1 || true
shell ../src/fiberfs_cmd -i >/dev/null 2>&1 || true
shell ../src/fiberfs_cmd -x >/dev/null 2>&1 || true
shell ../src/fiberfs_cmd -p _unknown_file.error_ >/dev/null 2>&1 || true
shell ../src/fiberfs_cmd -i _unknown_file.error_ >/dev/null 2>&1 || true

# Unmount

fs_test_release_all_wait 1

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
