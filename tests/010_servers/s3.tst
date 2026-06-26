fiber_test "FiberFS mock s3"

# Mock an S3 and config

set_timeout_sec 0

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init 0
cstore_mock_s3 0 region access_key secret_key

equal $cstore_server_tls:0 0

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
shell printf '"LOG_ALWAYS_FLUSH = true\n"' >> $var1

print "### CONFIG"

shell cat $var1

print "### MOUNT"

sys_mkdir_tmp

shell echo ./fiberfs_log $sys_tmpdir
shell echo ./fiberfs $var1 $sys_tmpdir

shell while [ -f $var1 ]; do sleep 1; done

cstore_debug
