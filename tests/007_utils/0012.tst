fiber_test "Config files real"

sys_mkdir_tmp

set conf_file $sys_tmpdir "/config"

shell printf '"one=1\\ntwo = 22"' > $conf_file

config_file $conf_file

equal $config:one 1
equal $config:two 22
