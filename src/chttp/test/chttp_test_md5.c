/*
 * Copyright (c) 2021 chttp
 *
 * Derived from the RSA Data Security, Inc. MD5 Message Digest Algorithm
 *
 */

#include "test/fbr_test.h"
#include "test/chttp_test_cmds.h"

#include <stdlib.h>

static unsigned char _MD5_PADDING[64] = {
	0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define FF(a, b, c, d, x, s, ac)					\
	do {								\
		(a) += F((b), (c), (d)) + (x) + (uint32_t)(ac);		\
		(a) = ROTATE_LEFT((a), (s));				\
		(a) += (b);						\
	} while (0)
#define GG(a, b, c, d, x, s, ac)					\
	do {								\
		(a) += G((b), (c), (d)) + (x) + (uint32_t)(ac);		\
		(a) = ROTATE_LEFT((a), (s));				\
		(a) += (b);						\
	} while (0)
#define HH(a, b, c, d, x, s, ac)					\
	do {								\
		(a) += H((b), (c), (d)) + (x) + (uint32_t)(ac);		\
		(a) = ROTATE_LEFT((a), (s));				\
		(a) += (b);						\
	} while (0)
#define II(a, b, c, d, x, s, ac)					\
	do {								\
		(a) += I((b), (c), (d)) + (x) + (uint32_t)(ac);		\
		(a) = ROTATE_LEFT((a), (s));				\
		(a) += (b);						\
	} while (0)

void
chttp_test_md5_init(struct chttp_test_md5 *md5)
{
	chttp_ZERO(md5);

	md5->i[0] = 0;
	md5->i[1] = 0;

	md5->buf[0] = (uint32_t)0x67452301;
	md5->buf[1] = (uint32_t)0xefcdab89;
	md5->buf[2] = (uint32_t)0x98badcfe;
	md5->buf[3] = (uint32_t)0x10325476;

	md5->magic = CHTTP_TEST_MD5_MAGIC;
	md5->ready = 0;
}

static void
_md5_transform(uint32_t *buf, uint32_t *in)
{
	uint32_t a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	/* Round 1 */
	#define S11 7
	#define S12 12
	#define S13 17
	#define S14 22
	FF(a, b, c, d, in[ 0], S11, 3614090360); /* 1 */
	FF(d, a, b, c, in[ 1], S12, 3905402710); /* 2 */
	FF(c, d, a, b, in[ 2], S13,  606105819); /* 3 */
	FF(b, c, d, a, in[ 3], S14, 3250441966); /* 4 */
	FF(a, b, c, d, in[ 4], S11, 4118548399); /* 5 */
	FF(d, a, b, c, in[ 5], S12, 1200080426); /* 6 */
	FF(c, d, a, b, in[ 6], S13, 2821735955); /* 7 */
	FF(b, c, d, a, in[ 7], S14, 4249261313); /* 8 */
	FF(a, b, c, d, in[ 8], S11, 1770035416); /* 9 */
	FF(d, a, b, c, in[ 9], S12, 2336552879); /* 10 */
	FF(c, d, a, b, in[10], S13, 4294925233); /* 11 */
	FF(b, c, d, a, in[11], S14, 2304563134); /* 12 */
	FF(a, b, c, d, in[12], S11, 1804603682); /* 13 */
	FF(d, a, b, c, in[13], S12, 4254626195); /* 14 */
	FF(c, d, a, b, in[14], S13, 2792965006); /* 15 */
	FF(b, c, d, a, in[15], S14, 1236535329); /* 16 */

	/* Round 2 */
	#define S21 5
	#define S22 9
	#define S23 14
	#define S24 20
	GG(a, b, c, d, in[ 1], S21, 4129170786); /* 17 */
	GG(d, a, b, c, in[ 6], S22, 3225465664); /* 18 */
	GG(c, d, a, b, in[11], S23,  643717713); /* 19 */
	GG(b, c, d, a, in[ 0], S24, 3921069994); /* 20 */
	GG(a, b, c, d, in[ 5], S21, 3593408605); /* 21 */
	GG(d, a, b, c, in[10], S22,   38016083); /* 22 */
	GG(c, d, a, b, in[15], S23, 3634488961); /* 23 */
	GG(b, c, d, a, in[ 4], S24, 3889429448); /* 24 */
	GG(a, b, c, d, in[ 9], S21,  568446438); /* 25 */
	GG(d, a, b, c, in[14], S22, 3275163606); /* 26 */
	GG(c, d, a, b, in[ 3], S23, 4107603335); /* 27 */
	GG(b, c, d, a, in[ 8], S24, 1163531501); /* 28 */
	GG(a, b, c, d, in[13], S21, 2850285829); /* 29 */
	GG(d, a, b, c, in[ 2], S22, 4243563512); /* 30 */
	GG(c, d, a, b, in[ 7], S23, 1735328473); /* 31 */
	GG(b, c, d, a, in[12], S24, 2368359562); /* 32 */

	/* Round 3 */
	#define S31 4
	#define S32 11
	#define S33 16
	#define S34 23
	HH(a, b, c, d, in[ 5], S31, 4294588738); /* 33 */
	HH(d, a, b, c, in[ 8], S32, 2272392833); /* 34 */
	HH(c, d, a, b, in[11], S33, 1839030562); /* 35 */
	HH(b, c, d, a, in[14], S34, 4259657740); /* 36 */
	HH(a, b, c, d, in[ 1], S31, 2763975236); /* 37 */
	HH(d, a, b, c, in[ 4], S32, 1272893353); /* 38 */
	HH(c, d, a, b, in[ 7], S33, 4139469664); /* 39 */
	HH(b, c, d, a, in[10], S34, 3200236656); /* 40 */
	HH(a, b, c, d, in[13], S31,  681279174); /* 41 */
	HH(d, a, b, c, in[ 0], S32, 3936430074); /* 42 */
	HH(c, d, a, b, in[ 3], S33, 3572445317); /* 43 */
	HH(b, c, d, a, in[ 6], S34,   76029189); /* 44 */
	HH(a, b, c, d, in[ 9], S31, 3654602809); /* 45 */
	HH(d, a, b, c, in[12], S32, 3873151461); /* 46 */
	HH(c, d, a, b, in[15], S33,  530742520); /* 47 */
	HH(b, c, d, a, in[ 2], S34, 3299628645); /* 48 */

	/* Round 4 */
	#define S41 6
	#define S42 10
	#define S43 15
	#define S44 21
	II(a, b, c, d, in[ 0], S41, 4096336452); /* 49 */
	II(d, a, b, c, in[ 7], S42, 1126891415); /* 50 */
	II(c, d, a, b, in[14], S43, 2878612391); /* 51 */
	II(b, c, d, a, in[ 5], S44, 4237533241); /* 52 */
	II(a, b, c, d, in[12], S41, 1700485571); /* 53 */
	II(d, a, b, c, in[ 3], S42, 2399980690); /* 54 */
	II(c, d, a, b, in[10], S43, 4293915773); /* 55 */
	II(b, c, d, a, in[ 1], S44, 2240044497); /* 56 */
	II(a, b, c, d, in[ 8], S41, 1873313359); /* 57 */
	II(d, a, b, c, in[15], S42, 4264355552); /* 58 */
	II(c, d, a, b, in[ 6], S43, 2734768916); /* 59 */
	II(b, c, d, a, in[13], S44, 1309151649); /* 60 */
	II(a, b, c, d, in[ 4], S41, 4149444226); /* 61 */
	II(d, a, b, c, in[11], S42, 3174756917); /* 62 */
	II(c, d, a, b, in[ 2], S43,  718787259); /* 63 */
	II(b, c, d, a, in[ 9], S44, 3951481745); /* 64 */

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

void
chttp_test_md5_update(struct chttp_test_md5 *md5, uint8_t *input, size_t len)
{
	uint32_t in[16];
	int mdi;
	unsigned int i, ii;

	assert(md5->magic == CHTTP_TEST_MD5_MAGIC);
	assert_zero(md5->ready);

	mdi = (int)((md5->i[0] >> 3) & 0x3F);

	if ((md5->i[0] + ((uint32_t)len << 3)) < md5->i[0]) {
		md5->i[1]++;
	}

	md5->i[0] += ((uint32_t)len << 3);
	md5->i[1] += ((uint32_t)len >> 29);

	while (len--) {
		md5->in[mdi++] = *input++;

		if (mdi == 0x40) {
			for (i = 0, ii = 0; i < 16; i++, ii += 4) {
				in[i] = (((uint32_t)md5->in[ii+3]) << 24) |
					(((uint32_t)md5->in[ii+2]) << 16) |
					(((uint32_t)md5->in[ii+1]) << 8) |
					((uint32_t)md5->in[ii]);
			}
			_md5_transform(md5->buf, in);
			mdi = 0;
		}
	}
}

void
chttp_test_md5_final(struct chttp_test_md5 *md5)
{
	uint32_t in[16];
	unsigned int pad_len, i, ii;
	int mdi;

	assert(md5->magic == CHTTP_TEST_MD5_MAGIC);
	assert_zero(md5->ready);

	in[14] = md5->i[0];
	in[15] = md5->i[1];

	mdi = (int)((md5->i[0] >> 3) & 0x3F);
	pad_len = (mdi < 56) ? (56 - mdi) : (120 - mdi);

	chttp_test_md5_update(md5, _MD5_PADDING, pad_len);

	for (i = 0, ii = 0; i < 14; i++, ii += 4) {
		in[i] = (((uint32_t)md5->in[ii+3]) << 24) |
			(((uint32_t)md5->in[ii+2]) << 16) |
			(((uint32_t)md5->in[ii+1]) << 8) |
			((uint32_t)md5->in[ii]);
	}

	_md5_transform(md5->buf, in);

	/* store buffer in digest */
	for (i = 0, ii = 0; i < 4; i++, ii += 4) {
		md5->digest[ii] = (unsigned char)(md5->buf[i] & 0xFF);
		md5->digest[ii+1] = (unsigned char)((md5->buf[i] >> 8) & 0xFF);
		md5->digest[ii+2] = (unsigned char)((md5->buf[i] >> 16) & 0xFF);
		md5->digest[ii+3] = (unsigned char)((md5->buf[i] >> 24) & 0xFF);
	}

	md5->ready = 1;
}

void
chttp_test_md5_store(struct chttp_test_md5 *md5, char *md5_buf)
{
	int len;

	assert(md5->magic == CHTTP_TEST_MD5_MAGIC);
	assert(md5->ready);
	assert(CHTTP_TEST_MD5_BUFLEN > 32);

	len = snprintf(md5_buf, CHTTP_TEST_MD5_BUFLEN,
		"%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x"
		"%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x",
			md5->digest[0], md5->digest[1], md5->digest[2], md5->digest[3],
			md5->digest[4], md5->digest[5], md5->digest[6], md5->digest[7],
			md5->digest[8], md5->digest[9], md5->digest[10], md5->digest[11],
			md5->digest[12], md5->digest[13], md5->digest[14], md5->digest[15]);
	assert(len == 32);
}

void
chttp_test_md5_store_server(struct fbr_test_context *ctx, struct chttp_test_md5 *md5)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);

	chttp_test_md5_store(md5, ctx->chttp_test->md5_server);
}

void
chttp_test_md5_store_client(struct fbr_test_context *ctx, struct chttp_test_md5 *md5)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);

	chttp_test_md5_store(md5, ctx->chttp_test->md5_client);
}

char *
chttp_test_var_md5_server(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	assert(strlen(ctx->chttp_test->md5_server) == 32);

	return ctx->chttp_test->md5_server;
}

char *
chttp_test_var_md5_client(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	assert(strlen(ctx->chttp_test->md5_client) == 32);

	return ctx->chttp_test->md5_client;
}

/*
int main(int argc, char **argv) {
	(void)argc;
	(void)argv;

	struct chttp_test_md5 md5;
	chttp_test_md5_init(&md5);
	chttp_test_md5_update(&md5, (unsigned char*)"test", 4);
	chttp_test_md5_update(&md5, (unsigned char*)"abc", 3);
	chttp_test_md5_final(&md5);

	printf("%2.2x%2.2x%2.2x%2.2x", md5.digest[0], md5.digest[1], md5.digest[2], md5.digest[3]);
	printf("%2.2x%2.2x%2.2x%2.2x", md5.digest[4], md5.digest[5], md5.digest[6], md5.digest[7]);
	printf("%2.2x%2.2x%2.2x%2.2x", md5.digest[8], md5.digest[9], md5.digest[10], md5.digest[11]);
	printf("%2.2x%2.2x%2.2x%2.2x\n", md5.digest[12], md5.digest[13], md5.digest[14],
		md5.digest[15]);

	printf("expected: ca2b67db58c83f0e184663098bcb74b8\n");
}
*/
