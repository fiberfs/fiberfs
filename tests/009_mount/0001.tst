fiber_test "FiberFS mounting"

# Mock an S3 and config

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 0
cstore_mock_s3 0 region access_key secret_key

sys_mkdir_tmp
set_var1 $sys_tmpdir "/config"

sys_mkdir_tmp

shell printf '"S3_HOST=%s\n"' $cstore_server_host:0 > $var1
shell printf '"S3_PORT=%s\n"' $cstore_server_port:0 >> $var1
shell printf '"S3_TLS=false\n"' >> $var1
shell printf '"S3_REGION=region\n"' >> $var1
shell printf '"S3_ACCESS_KEY=access_key\n"' >> $var1
shell printf '"S3_SECRET_KEY=secret_key\n"' >> $var1
shell printf '"CACHE_ROOT=%s\n"' $sys_tmpdir >> $var1

sys_mkdir_tmp

# Mount fiberfs

print "### FIRST MOUNT"

shell_bg ../src/fiberfs $var1 $sys_tmpdir >/dev/null 2>&1

equal $cstore_stat_roots:0 1
equal $cstore_stat_indexes:0 1
equal $cstore_stat_root_updates:0 1
equal $cstore_stat_http_200:0 2
greater_than $cstore_stat_http_400:0 0
equal $cstore_stat_http_500:0 0

#shell_bg ../src/fiberfs_log $sys_tmpdir

shell ps -ef | grep "[f]iberfs\ " | grep -v '" sh "' | grep $sys_tmpdir | awk "'{print $2}'" | xargs kill

shell_waitall

cstore_debug

# Remount fiberfs

sleep_ms 200

print "### SECOND MOUNT"

shell_bg ../src/fiberfs $var1 $sys_tmpdir >/dev/null 2>&1

sleep_ms 200

sys_ls $sys_tmpdir

equal $cstore_stat_roots:0 1
equal $cstore_stat_indexes:0 1
equal $cstore_stat_root_updates:0 1
greater_equal $cstore_stat_http_200:0 2
equal $cstore_stat_http_500:0 0

#shell_bg ../src/fiberfs_log $sys_tmpdir

shell ps -ef | grep "[f]iberfs\ " | grep -v '" sh "' | grep $sys_tmpdir | awk "'{print $2}'" | xargs kill

shell_waitall

cstore_debug
