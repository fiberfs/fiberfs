fiber_test "cstore server"

config_add CSTORE_SERVER true
config_add CSTORE_SERVER_ADDRESS "127.0.0.1"
config_add CSTORE_SERVER_PORT 0

cstore_init
cstore_init 1
cstore_set_s3 1 "" 0 region access_key secret_key

config_add CSTORE_SERVER_TLS true
cstore_tls_timeout
cstore_init 2

sleep_ms 100

chttp_init
chttp_url /
chttp_connect $cstore_server_host:0 $cstore_server_port:0
chttp_send
chttp_status_match 400

chttp_reset
chttp_url /
chttp_add_header "host" "hostname"
chttp_s3_sign hostname region access_key secret_key
chttp_connect $cstore_server_host:1 $cstore_server_port:1
chttp_send
chttp_status_match 400

equal $cstore_server_tls:2 1

chttp_reset
chttp_url /
chttp_connect $cstore_server_host:2 $cstore_server_port:2 1
chttp_send
chttp_status_match 400
