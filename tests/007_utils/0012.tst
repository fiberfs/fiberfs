fiber_test "Config files real"

sys_mkdir_tmp

set_var1 $sys_tmpdir "/config"

shell printf '"one=1\\ntwo = 22"' > $var1

config_file $var1

equal $config:one 1
equal $config:two 22
