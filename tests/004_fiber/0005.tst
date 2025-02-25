fiber_test "Fuse and fs"

sys_mkdir_tmp

fs_test_fuse_mount $sys_tmpdir

sys_ls $sys_tmpdir

sleep_ms 100

set_var1 $sys_tmpdir "/fiber_dir02"
sys_ls $var1

sleep_ms 100

set_var2 $var1 "/fiber_dir13"
sys_ls $var2

sleep_ms 100

fs_test_release_root
fs_test_stats
equal $fs_test_stat_directories 0
equal $fs_test_stat_files 2
equal $fs_test_stat_file_refs 2

fuse_test_unmount
