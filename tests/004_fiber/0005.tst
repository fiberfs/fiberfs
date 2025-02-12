fiber_test "Fuse and fs"

fs_mkdir_tmp

fs_test_fuse_mount $fs_tmpdir

fs_test_stats

#fs_ls $fs_tmpdir

set_var1 $fs_tmpdir "/fiber2"
fs_cat $var1

fs_test_release_root

fs_test_stats

fuse_test_unmount
