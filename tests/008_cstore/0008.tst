fiber_test "cstore server"

cstore_enable_server 127.0.0.1 0
cstore_init
cstore_init_1
cstore_init_2

chttp_init
chttp_url /
chttp_connect $cstore_server_host $cstore_server_port
chttp_send
chttp_status_match 400

chttp_reset
chttp_url /
chttp_connect $cstore_1_server_host $cstore_1_server_port
chttp_send
chttp_status_match 400

chttp_reset
chttp_url /
chttp_connect $cstore_2_server_host $cstore_2_server_port
chttp_send
chttp_status_match 400
