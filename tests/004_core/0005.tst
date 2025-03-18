fiber_test "Filename tests"

fs_test_path_assert

fs_test_path
fs_test_path "one" "two" "three" "four"
fs_test_path 12345678901234567890 1234567890 1234567890
fs_test_path 12345678901234 x
