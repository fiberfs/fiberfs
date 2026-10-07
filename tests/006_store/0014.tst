fiber_test "Threaded append error test"

config_add LOG_SIZE 3000000

append_thread_error_test
