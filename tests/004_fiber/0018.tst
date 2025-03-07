fiber_test "Mount fs fuse and do external tests for 2 minutes"

# Init

skip_if_valgrind

set_timeout_sec 30

sys_mkdir_tmp
fs_test_fuse_mount $sys_tmpdir
fs_test_dentry_ttl_ms 0
fs_test_fuse_init_root

print "### Test 1"

set_var1 "cd " $sys_tmpdir "; sleep 0.04; cat * */* */*/* >/dev/null 2>&1 &"
set_var2 "cd " $sys_tmpdir "; sleep 0.02; cat * */* */*/* >/dev/null 2>&1 &"
set_var3 "cd " $sys_tmpdir "; cat * */* */*/* >/dev/null 2>&1 || true"

shell $var1
shell $var2

# TODO this causes failure...
#fs_test_release_root 0
fs_test_stats
fs_test_debug

sleep_ms 1000

print "### Done, doing cleanup"

fs_test_release_root

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

print "### EXIT"
