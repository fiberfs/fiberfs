fiber_test "cstore server"

cstore_enable_server
cstore_init

chttp_init
chttp_url /
chttp_connect 127.0.0.1 5691
chttp_send_only
