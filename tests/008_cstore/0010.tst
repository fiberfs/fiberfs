fiber_test "cstore server PUT/GET with s3"

server_init
server_accept

# PUT fiberfsindex
server_read_request
server_header_exists "Content-Length"
server_body_read
server_send_response

# PUT fiberfsroot
server_read_request
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

#set_var1 $sys_tmpdir "/test.txt"
#sys_write $var1 "content!"

sleep_ms 100

print "### READ"

#sys_cat $var1 "CONTENT~"
