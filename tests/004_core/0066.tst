fiber_test "xattr"

# Mount

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Setup

set file $sys_tmpdir "/somefile"
sys_truncate $file 0

# xattr

sys_xattr_list $sys_tmpdir ".fiberfs,user.fiberfs"
sys_xattr_list $file ".fiberfs,user.fiberfs"

sys_xattr_get $sys_tmpdir "user.fiberfs" $fiberfs_version
sys_xattr_get $sys_tmpdir ".fiberfs" $fiberfs_version
sys_xattr_get $file "user.fiberfs" $fiberfs_version
sys_xattr_get $file ".fiberfs" $fiberfs_version

# Validate

sleep_ms 10
fs_test_release_all_wait

sys_ls $sys_tmpdir "..:dir .:dir somefile:file"
sys_stat_size $file 0

# Cleanup

fs_test_release_all_wait 1
equal $fs_test_stat_files_inodes 0

cstore_wait 0

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
