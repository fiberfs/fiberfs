fiber_test "cstore with lru"

set_timeout_sec 25

cstore_init
cstore_test_lru
