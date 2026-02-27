fiber_test "Store write with flush errors"

config_add LOG_SIZE 150000

store_write_error_flush
