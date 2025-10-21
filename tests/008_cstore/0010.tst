fiber_test "cstore server PUT/GET with s3"

server_init
server_accept

# PUT fiberfsindex
server_read_request
server_method_match PUT
server_url_submatch ".fiberfsindex"
server_header_exists "Content-Length"
server_body_read
server_send_response

# PUT fiberfsroot
server_read_request
server_method_match PUT
server_url_submatch ".fiberfsroot"
server_header_exists "Content-Length"
server_body_read
server_send_response

cstore_init 0
cstore_set_s3 0 $server_host $server_port

sys_mkdir_tmp
fs_test_rw_mount $sys_tmpdir
test_log_always_flush

sleep_ms 100

print "### WRITE"

# PUT test.txt
server_read_request
server_method_match PUT
server_url_submatch "test.txt"
server_header_exists "Content-Length"
server_body_match "content_here"
server_send_response

# PUT fiberfsindex
server_read_request
server_method_match PUT
server_url_submatch ".fiberfsindex"
server_header_exists "Content-Length"
server_body_read
server_send_response

# PUT fiberfsroot
server_read_request
server_method_match PUT
server_url_submatch ".fiberfsroot"
server_header_exists "Content-Length"
server_body_read
server_send_response

# DELETE fiberfsindex
server_read_request
server_method_match DELETE
server_url_submatch ".fiberfsindex"
server_send_response

set_var1 $sys_tmpdir "/test.txt"
sys_write $var1 "content_here"

sleep_ms 100

cstore_debug
equal $cstore_0_entries 3
