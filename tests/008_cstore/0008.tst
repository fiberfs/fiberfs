fiber_test "cstore server"

skip

cstore_enable_server
cstore_init

chttp_init
chttp_url /
# TODO turn these into variables
chttp_connect 127.0.0.1 5691
chttp_send
chttp_status_match 200
