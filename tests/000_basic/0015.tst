fiber_test "Forking"

fs_mkdir_tmp
print $fs_tmpdir
fork print $fs_tmpdir
vfork print "1" 2 "3" ": " $fs_tmpdir "."
print $fs_tmpdir
