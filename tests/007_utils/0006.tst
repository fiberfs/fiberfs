fiber_test "chashes sha256 and md5"

set_timeout_sec 120

test_sha256
test_hmac_sha256
test_md5
test_sha256_openssl
