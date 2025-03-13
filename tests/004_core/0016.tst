fiber_test "File reading big and page cache"

# Init

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir
fs_test_dentry_ttl_ms 200
fs_test_fuse_init_root

# Do read

print "### READ 1"

set_var1 $sys_tmpdir "/fiber_big"
sys_stat_size $var1 1048576
sys_cat_md5 $var1 4cf30131c206e004d37e694a53733f70

equal $fs_test_stat_read_bytes 1048576

print "### READ 2"

sleep_ms 100

sys_cat_md5 $var1 4cf30131c206e004d37e694a53733f70

equal $fs_test_stat_read_bytes 1048576

# Cache clear 

print "### SLEEP PAST TTL"

sleep_ms 200
fs_test_stats
fs_test_debug

# Read again

print "### READ 3"

sys_cat_md5 $var1 4cf30131c206e004d37e694a53733f70

equal $fs_test_stat_read_bytes 1048576

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
equal $fs_test_stat_files 1
equal $fs_test_stat_files_inodes 1
equal $fs_test_stat_read_bytes 1048576
equal $fs_test_stat_fetch_bytes 1672964

fuse_test_unmount
