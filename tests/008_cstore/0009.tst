fiber_test "cstore server PUT"

cstore_enable_server 127.0.0.1 0
cstore_init

chttp_init
chttp_method PUT
chttp_url /file.txt.17592574420817011762.55
chttp_add_header "ETag" '"17592574420817011762"'
chttp_add_header "Content-Length" "10"
chttp_connect $cstore_server_host $cstore_server_port
chttp_send_only
chttp_send_body "chunk_here"
chttp_receive
chttp_status_match 200

cstore_debug

chttp_reset
# TODO
chttp_new_connection
chttp_method GET
chttp_url /file.txt.17592574420817011762.55
chttp_connect $cstore_server_host $cstore_server_port
chttp_send
chttp_status_match 200
chttp_body_match "chunk_here"
