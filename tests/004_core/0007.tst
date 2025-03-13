fiber_test "Fuse and fs"

# Init

set_timeout_sec 20

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir
fs_test_dentry_ttl_ms 0
fs_test_fuse_init_root

# Do a bunch of operations

print "### TEST 1"

sys_ls $sys_tmpdir

set_var1 $sys_tmpdir "/fiber_dir02"
sys_ls $var1

set_var2 $var1 "/fiber_dir13"
sys_ls $var2

set_var3 $sys_tmpdir "/fiber_dir03/fiber_dir11/fiber_dir24/fiber_dir33"
sys_ls $var3 "..:dir .:dir fiber_41:file fiber_42:file fiber_43:file fiber_44:file fiber_dir41:dir fiber_dir42:dir fiber_dir43:dir fiber_dir44:dir"

set_var4 $sys_tmpdir "/fiber_dir03/fiber_dir11/"
sys_ls $var4

set_var5 $sys_tmpdir "/fiber_dir03/fiber_dir11/fiber_dir21/fiber_dir32/fiber_dir44"
sys_ls $var5 "..:dir .:dir fiber_51:file fiber_52:file fiber_53:file fiber_54:file"

# Expire cache

print "### TEST 2 (release root)"

sleep_ms 100
fs_test_stats
fs_test_debug

fs_test_release_all

sleep_ms 100
fs_test_stats
fs_test_debug

# New operations

print "### TEST 3 (more operations)"

sys_ls $sys_tmpdir
sys_ls $var1
sys_ls $var2

# Cleanup

sleep_ms 100
fs_test_stats
fs_test_debug

fs_test_release_all 1

sleep_ms 100
fs_test_stats
fs_test_debug

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
