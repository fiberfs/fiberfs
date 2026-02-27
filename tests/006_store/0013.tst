fiber_test "Threaded append test"

config_add LOG_SIZE 1000000

append_thread_test
