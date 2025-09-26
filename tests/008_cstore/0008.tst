fiber_test "cstore server"

cstore_enable_server 127.0.0.1 0
cstore_init

chttp_init
chttp_url /
chttp_connect $cstore_server_host $cstore_server_port
chttp_send
chttp_status_match 200
