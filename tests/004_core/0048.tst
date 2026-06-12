fiber_test "rmdir 2fs test cluster"

set_timeout_sec 25
config_add LOG_SIZE 250000

rmdir_2fs_test_cluster
