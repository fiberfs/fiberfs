fiber_test "File reading"

# Init

set_timeout_sec 30

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir
fs_test_fuse_init_root

# Do operations

print "### TEST 1 (read tests)"

set_var1 $sys_tmpdir "/fiber_03"
sys_stat_size $var1 0
sys_cat_md5 $var1 d41d8cd98f00b204e9800998ecf8427e

set_var1 $sys_tmpdir "/fiber_dir01/fiber_12"
sys_stat_size $var1 2002
sys_cat_md5 $var1 1f7c1e8fcd523b2fb38991706806f210

set_var1 $sys_tmpdir "/fiber_dir01/fiber_dir11/fiber_24"
sys_stat_size $var1 8008
sys_cat_md5 $var1 560ecea077b5f4f29efdb6f41062af0d

set_var1 $sys_tmpdir "/fiber_zero"
sys_stat_size $var1 128125
sys_cat_md5 $var1 20395dbf890a189292bf2aafa6d4fb40

set_var1 $sys_tmpdir "/fiber_big"
sys_stat_size $var1 1048576
sys_cat_md5 $var1 4cf30131c206e004d37e694a53733f70

# Repeat read with everything cached

print "### TEST 2 (all cached)"

sleep_ms 100
fs_test_stats
fs_test_debug

set_var1 $sys_tmpdir "/fiber_dir01/fiber_dir11/fiber_24"
sys_stat_size $var1 8008
sys_cat_md5 $var1 560ecea077b5f4f29efdb6f41062af0d

# Drop and expire everything and get fresh inodes

print "### TEST 3 (directory expired, new inodes)"

sleep_ms 100
fs_test_stats
fs_test_debug

fs_test_release_all

sleep_ms 100
fs_test_stats
fs_test_debug

set_var1 $sys_tmpdir "/fiber_dir01/fiber_dir11/fiber_24"
sys_stat_size $var1 8008
sys_cat_md5 $var1 560ecea077b5f4f29efdb6f41062af0d

# Cleanup

print "### TEST 4 (cleanup)"

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
