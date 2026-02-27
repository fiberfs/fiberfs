fiber_test "cstore async"

config_add LOG_SIZE 1000000

cstore_async_test
