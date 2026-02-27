fiber_test "Threaded append error test"

config_add LOG_SIZE 1200000

append_thread_error_test
