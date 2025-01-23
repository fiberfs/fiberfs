fiber_test "Fuse test mounting"

set_timeout_sec 2

fs_mkdir_tmp

fuse_test $fs_tmpdir
