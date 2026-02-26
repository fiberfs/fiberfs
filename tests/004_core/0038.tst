fiber_test "root file config"

config_add FS_ROOT_MODE 777
config_add FS_ROOT_UID 123
config_add FS_ROOT_GID 456

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

shell ls -ld $sys_tmpdir

sys_stat_mode $sys_tmpdir 16895
sys_stat_uid $sys_tmpdir 123 456

fuse_test_unmount
