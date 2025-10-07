fiber_test "cstore server PUT/GET with s3"

cstore_enable_server 127.0.0.1 0
cstore_init 0
cstore_init 1

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir

