fiber_test "cstore with lru"

set_timeout_sec 25

sys_mkdir_tmp
cstore_init $sys_tmpdir

cstore_test_lru
