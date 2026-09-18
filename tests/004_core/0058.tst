fiber_test "Rename file"

# Init
config_add FUSE_WRITEBACK_CACHE false

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### Write file_orig"

set file $sys_tmpdir "/file_orig"
sys_write $file "renamed file"

sleep_ms 20

print "### Rename"

set file_new $sys_tmpdir "/file_NEW"
sys_rename $file $file_new

sleep_ms 20

print "### Verify"

sys_ls $sys_tmpdir "..:dir .:dir file_NEW:file"

sys_cat $file_new "renamed file"

sleep_ms 20

print "### Verify (index)"

fs_test_release_all_wait

sys_ls $sys_tmpdir "..:dir .:dir file_NEW:file"

sys_cat $file_new "renamed file"

sleep_ms 20

print "### Append"

sys_append $file_new "_chunky"

sys_cat $file_new "renamed file_chunky"

sleep_ms 20

print "### Verify (index 2)"

fs_test_release_all_wait

sys_ls $sys_tmpdir "..:dir .:dir file_NEW:file"

sys_cat $file_new "renamed file_chunky"

# Cleanup

print "### CLEANUP"

fs_test_release_all_wait 1

sleep_ms 20
fs_test_stats
fs_test_debug
cstore_debug

equal $cstore_stat_chunks:0 2

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
