fiber_test "Rename errors and overwriting"

# Init
config_add FUSE_WRITEBACK_CACHE false
config_add DEBUG_FS_WBUFFER_ALLOC_SIZE 3

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

# Operations

print "### Write files"

set file0 $sys_tmpdir "/file_zero"
set file1 $sys_tmpdir "/file_one"
set file2 $sys_tmpdir "/file_two"
set file3 $sys_tmpdir "/file_three"
set dir1 $sys_tmpdir "/directoryABC"
set dir2 $sys_tmpdir "/directory_one"
set dir1_file0 $dir1 "/file_zero"

sys_write $file1 "1234" "5678" "9012"
sys_write $file2 "123" "456" "7890"
sys_write $file3 "ABC" "DEF"
sys_mkdir $dir1
sys_mkdir $dir2

sleep_ms 20
print "### Rename no source"

rename_error $file0 $file2

sleep_ms 20
print "### Rename different directory"

rename_error $file1 $dir1_file0

sleep_ms 20
print "### Rename directory source"

rename_error $dir1 $file2
rename_error $dir1 $dir2

sleep_ms 20
print "### Rename directory dest"

rename_error $file1 $dir2
rename_error $dir1 $dir2

sleep_ms 20
print "### Rename bad flag"

rename_error $file1 $file2 2

sleep_ms 20
print "### Rename dest exists (UNIQUE)"

rename_error $file1 $file2 1

sleep_ms 20
print "### Rename file1 to file2 (delete old chunks)"

cstore_wait 0
equal $cstore_stat_chunks:0 8

sys_rename $file1 $file2

cstore_wait 0
equal $cstore_stat_chunks:0 5

sleep_ms 20
print "### Rename file3 to file2 (delete old aliased chunks)"

sys_rename $file3 $file2

cstore_wait 0
equal $cstore_stat_chunks:0 2

sleep_ms 20
print "### Write first chunk to file2 (file3 alias)"

sys_write_seek $file2 0 "ZXYW"

cstore_wait 0
equal $cstore_stat_chunks:0 2

sleep_ms 20
print "### Verify memory"

sys_ls $sys_tmpdir "..:dir .:dir directoryABC:dir directory_one:dir file_two:file"

sys_cat $file2 "ZXYWEF"

sleep_ms 20
print "### Verify index"

fs_test_release_all_wait

sys_ls $sys_tmpdir "..:dir .:dir directoryABC:dir directory_one:dir file_two:file"

sys_cat $file2 "ZXYWEF"

# Cleanup

sleep_ms 20
print "### CLEANUP"

fs_test_release_all_wait 1

sleep_ms 20
fs_test_stats
fs_test_debug
cstore_debug

equal $cstore_stat_roots:0 3
equal $cstore_stat_indexes:0 3
equal $cstore_stat_chunks:0 2

equal $fs_test_stat_directories 0
equal $fs_test_stat_directories_dindex 0
equal $fs_test_stat_directory_refs 0
equal $fs_test_stat_files 0
equal $fs_test_stat_files_inodes 0
equal $fs_test_stat_file_refs 0

fuse_test_unmount
