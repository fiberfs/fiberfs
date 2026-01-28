/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifdef CHTTP_OPENSSL

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "fiberfs.h"
#include "chttp_tls_openssl_test_key.h"

static const char *_TLS_OPENSSL_TEST_CERT =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIF5zCCA8+gAwIBAgIUHBpcPafJIKc1u7VBHIvk8sW6/w4wDQYJKoZIhvcNAQEL\n"
	"BQAwgYExCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQK\n"
	"DBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxGTAXBgNVBAMMEG51bGx0ZWNoLnN5\n"
	"c3RlbXMxHzAdBgkqhkiG9w0BCQEWEHJlemFAbmFnaGliaS5jb20wIBcNMjQxMDE3\n"
	"MTczNjIwWhgPMjA1MjAzMDMxNzM2MjBaMIGBMQswCQYDVQQGEwJBVTETMBEGA1UE\n"
	"CAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRk\n"
	"MRkwFwYDVQQDDBBudWxsdGVjaC5zeXN0ZW1zMR8wHQYJKoZIhvcNAQkBFhByZXph\n"
	"QG5hZ2hpYmkuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuQhm\n"
	"1kbytnlfSHtTmD9i0cmLjjGwrZpImV3Dk2YfFQLGbJGklMnr3Yimp3koB0nzQHtk\n"
	"aIwJ5UAJ5MJEQ4O1BPxnP43qhIxgR9NzxqgLJ8tTfRiaedh/Pq4a6D8UX6+8jEFf\n"
	"so0rgjnQjAShecJBcjdYkML2skJ0Dav0T5kpct+dVHM3+AXjyCSDQur6VkRA+CV/\n"
	"JQZNZ3y+Bn5/1P4J7NQqjwacVXRQej75ScGOXwY/H+/NjIPeq93NAlQ+eGMBdEqn\n"
	"UywlMe6rz3CbLbjlTzIs95d1J+wEKv5CgUsuX/Ry/QJKcJf1dLBd/HMu+ZUTeu8I\n"
	"ggzOPDPSP6TtCAisuQmS4jdfQev2tM8DU4Y5xBpQwx+GmizhLh437LvR5AYXYn5u\n"
	"/L+GgORNzWaun1MdT5lsRbYrHSyWrqcRfJ1RLlbhoxAZtTkeGh0CIYGC9gDNfA1K\n"
	"/eVgNGmMRnZ11vuNEXr5+EKCaQOwAdgQ1g8RocDaqW3TbbTyq+0X4O8cRpLc6v/E\n"
	"f2iBa+DCi5T/NaLYrkea6ni1kZAgDrKnZUqAUhlDGfD+s3MSAFWL1Q78T6iXToU5\n"
	"nHZw9T3n/afX/3KRwPaJvdirIL2zkDk4/7mi1FzOsy9euZT6Czr89v0wZxRTto5U\n"
	"6A0U5JTrEYuSkeLCQcl+w+suvh91Lh4oQFXH7VUCAwEAAaNTMFEwHQYDVR0OBBYE\n"
	"FLrod6n6EebpN5eI8/h9rP09D6IHMB8GA1UdIwQYMBaAFLrod6n6EebpN5eI8/h9\n"
	"rP09D6IHMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBADaHbHku\n"
	"QfY92QvCdjyB1/jJFnWpCIByPuf5Tj116g/e906gXNJRJVdAWeAUuFaObxAF5kMU\n"
	"2RdsANi8djqsW64ZCn6N4nQTPDoAvic2Hl2zO8Z9Ns1WyOVT+eKYEUgSOt2sqKuI\n"
	"4nXUte9eZJbqRQ1fhbcols2UNybfTYA7+PP23LYtLUzshdMkn0NrkV0W8bWtdEWZ\n"
	"9EA3rf8+Oo578THnQWdhnnFBKG4kYtQmYPSIg24feaVdDIDQ5rWxfGIhJTiBZoGL\n"
	"EakqTTe/13uxKrSvnjSV04mLcroRZCRiWa6nma30HnJEzPZMxE5CdwgTYxRuoiGn\n"
	"PSq0m73ANpe3Gm9x8Tr1i4/Gg3xVUOSITM2GTuNYmkmKVW88NG/Ouztrt08CZAWc\n"
	"7FauXdgCglULu7AsnN8F7eCib/2nzS4qu52Ezk1VZ65qbhjIAFCj8FiAJB/T4Xza\n"
	"yjXh8Ke/U4pp0Cv9l04A2b3aGN8xZiM1vTQNd8mZxQ/0FKAXvNxD5N4LcdDaQSPL\n"
	"DpnXfXCNbHnSKzCZRv/DrjGqL/Oio7QGbVj2iDa1Lq7P0L3Sr1H5FEeQIqAn3Y+J\n"
	"nUcfRsdE+boSx59b4zeHl6mpG8Fn5R4/tLd7Tpcf2jrhfh0BLoPdXNvL27cAJUq1\n"
	"p02qexPDQBjZRfS7zjsvkcvn4OavWTM+A5k0\n"
	"-----END CERTIFICATE-----\n";

static const char *_TLS_OPENSSL_TEST_KEY =
	"-----BEGIN PRIVATE KEY-----\n"
	"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\n"
	"oWhrNJhyQz7ZyLqHAo8I9hht3AyzuaA=\n"
	"-----END PRIVATE KEY-----\n";

void
chttp_openssl_test_key(void *ctx_priv)
{
	assert(ctx_priv);
	SSL_CTX *ctx = (SSL_CTX*)ctx_priv;

	BIO *bio = BIO_new_mem_buf(_TLS_OPENSSL_TEST_CERT, -1);
	assert(bio);

	X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	assert(cert);

	int ret = SSL_CTX_use_certificate(ctx, cert);
	assert(ret == 1);

	BIO_free(bio);
	X509_free(cert);

	bio = BIO_new_mem_buf(_TLS_OPENSSL_TEST_KEY, -1);
	assert(bio);

	EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	assert(key);

	ret = SSL_CTX_use_PrivateKey(ctx, key);
	assert(ret == 1);

	BIO_free(bio);
	EVP_PKEY_free(key);
}

#endif /* CHTTP_OPENSSL */
