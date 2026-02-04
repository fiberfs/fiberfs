fiber_test "Config params"

config_add test value
config_add var123 ABC

print $config:test
equal $config:var123 ABC
