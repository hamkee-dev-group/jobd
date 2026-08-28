#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "jobd.h"
#include "testutil.h"

static void test_magic(void)
{
	TEST("magic value");
	ASSERT(JOBD_PROTO_MAGIC == 0x4A424431u, "magic mismatch");
	PASS();
}

static void test_header_wire_size(void)
{
	TEST("header wire size is 20 bytes");
	ASSERT(JOBD_HDR_WIRE_SIZE == 20, "header wire size changed");
	PASS();
}

static void test_codec_roundtrip(void)
{
	TEST("integer codec round trip");

	uint8_t buf[64];
	struct agd_wr w;
	agd_wr_init(&w, buf, sizeof(buf));

	agd_wr_u8(&w, 0xAB);
	agd_wr_u16(&w, 0x1234);
	agd_wr_u32(&w, 0xDEADBEEFu);
	agd_wr_u64(&w, 0x0123456789ABCDEFULL);
	ASSERT(agd_wr_ok(&w), "writer overflowed");

	struct agd_rd r;
	agd_rd_init(&r, buf, w.len);

	uint8_t v8; uint16_t v16; uint32_t v32; uint64_t v64;
	agd_rd_u8(&r, &v8);
	agd_rd_u16(&r, &v16);
	agd_rd_u32(&r, &v32);
	agd_rd_u64(&r, &v64);

	ASSERT(agd_rd_ok(&r), "reader failed");
	ASSERT(v8 == 0xAB, "u8 mismatch");
	ASSERT(v16 == 0x1234, "u16 mismatch");
	ASSERT(v32 == 0xDEADBEEFu, "u32 mismatch");
	ASSERT(v64 == 0x0123456789ABCDEFULL, "u64 mismatch");
	PASS();
}

static void test_codec_is_little_endian(void)
{
	TEST("codec is little endian on every host");

	uint8_t buf[4];
	struct agd_wr w;
	agd_wr_init(&w, buf, sizeof(buf));
	agd_wr_u32(&w, 0x01020304u);

	ASSERT(buf[0] == 0x04 && buf[1] == 0x03 &&
	       buf[2] == 0x02 && buf[3] == 0x01,
	       "byte order is not little endian");
	PASS();
}

static void test_writer_refuses_overflow(void)
{
	TEST("writer refuses to overflow its buffer");

	uint8_t buf[4];
	struct agd_wr w;
	agd_wr_init(&w, buf, sizeof(buf));

	agd_wr_u32(&w, 1);
	ASSERT(agd_wr_ok(&w), "first write should fit");
	agd_wr_u8(&w, 1);
	ASSERT(!agd_wr_ok(&w), "overflowing write should be flagged");
	ASSERT(w.len == 4, "length must not grow past capacity");
	PASS();
}

static void test_reader_refuses_short_read(void)
{
	TEST("reader refuses to read past the payload");

	uint8_t buf[2] = { 1, 2 };
	struct agd_rd r;
	agd_rd_init(&r, buf, sizeof(buf));

	uint32_t v;
	ASSERT(agd_rd_u32(&r, &v) != 0, "should not read 4 bytes from 2");
	ASSERT(!agd_rd_ok(&r), "error flag should be set");
	PASS();
}

static void test_str_does_not_truncate(void)
{
	TEST("string read fails rather than truncating");

	uint8_t buf[64];
	struct agd_wr w;
	agd_wr_init(&w, buf, sizeof(buf));
	agd_wr_str(&w, "0123456789");

	char small[4];
	struct agd_rd r;
	agd_rd_init(&r, buf, w.len);
	ASSERT(agd_rd_str(&r, small, sizeof(small)) != 0,
	       "an oversized string must be rejected, not truncated");

	char big[32];
	agd_rd_init(&r, buf, w.len);
	ASSERT(agd_rd_str(&r, big, sizeof(big)) == 0, "should fit");
	ASSERT(strcmp(big, "0123456789") == 0, "content mismatch");
	PASS();
}

static void test_count_limit(void)
{
	TEST("count read enforces its limit");

	uint8_t buf[8];
	struct agd_wr w;
	agd_wr_init(&w, buf, sizeof(buf));
	agd_wr_u32(&w, 500);

	struct agd_rd r;
	uint32_t n;
	agd_rd_init(&r, buf, w.len);
	ASSERT(agd_rd_count(&r, 64, &n) != 0, "500 should exceed a limit of 64");

	agd_rd_init(&r, buf, w.len);
	ASSERT(agd_rd_count(&r, 1000, &n) == 0 && n == 500, "should accept 500");
	PASS();
}

static void test_send_recv_roundtrip(void)
{
	TEST("send/recv round trip over a socket pair");

	int fds[2];
	ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair failed");

	const char *body = "payload contents";
	struct jobd_msg_header send_hdr = {
		.magic       = JOBD_PROTO_MAGIC,
		.version     = JOBD_PROTO_VERSION,
		.type        = JOBD_MSG_INSPECT,
		.payload_len = (uint32_t)strlen(body),
		.request_id  = 0x1122334455667788ULL,
	};

	ASSERT(jobd_send_msg(fds[0], &send_hdr, (const uint8_t *)body) == 0,
	       "send failed");

	struct jobd_msg_header recv_hdr;
	uint8_t buf[256];
	size_t received = 0;
	ASSERT(jobd_recv_msg(fds[1], &recv_hdr, buf, sizeof(buf),
	                       &received) == 0, "recv failed");

	ASSERT(recv_hdr.magic == send_hdr.magic, "magic mismatch");
	ASSERT(recv_hdr.type == send_hdr.type, "type mismatch");
	ASSERT(recv_hdr.request_id == send_hdr.request_id, "request id mismatch");
	ASSERT(received == strlen(body), "payload length mismatch");
	ASSERT(memcmp(buf, body, received) == 0, "payload mismatch");

	close(fds[0]);
	close(fds[1]);
	PASS();
}

static void test_response_roundtrip(void)
{
	TEST("response round trip");

	int fds[2];
	ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair failed");

	const char *body = "result text";
	ASSERT(jobd_send_response(fds[0], 99, JOBD_STATUS_ERR_VALIDATE,
	                            (const uint8_t *)body,
	                            (uint32_t)strlen(body)) == 0, "send failed");

	struct jobd_msg_header hdr;
	uint8_t buf[256];
	size_t received = 0;
	ASSERT(jobd_recv_msg(fds[1], &hdr, buf, sizeof(buf), &received) == 0,
	       "recv failed");
	ASSERT(hdr.type == JOBD_MSG_RESPONSE, "type should be RESPONSE");

	struct jobd_response resp;
	const uint8_t *data = NULL;
	ASSERT(jobd_parse_response(buf, received, &resp, &data) == 0,
	       "parse failed");
	ASSERT(resp.status == JOBD_STATUS_ERR_VALIDATE, "status mismatch");
	ASSERT(resp.result_len == strlen(body), "result length mismatch");
	ASSERT(memcmp(data, body, resp.result_len) == 0, "result mismatch");

	close(fds[0]);
	close(fds[1]);
	PASS();
}

static void test_oversized_payload_rejected(void)
{
	TEST("oversized payload_len is rejected");

	int fds[2];
	ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair failed");

	struct jobd_msg_header hdr = {
		.magic       = JOBD_PROTO_MAGIC,
		.version     = JOBD_PROTO_VERSION,
		.type        = JOBD_MSG_RUN,
		.payload_len = 0xFFFFFFFFu,
		.request_id  = 1,
	};
	jobd_send_msg(fds[0], &hdr, NULL);

	struct jobd_msg_header rhdr;
	uint8_t buf[16];
	ASSERT(jobd_recv_msg(fds[1], &rhdr, buf, sizeof(buf), NULL) == -4,
	       "should reject an oversized payload_len");

	close(fds[0]);
	close(fds[1]);
	PASS();
}

static void test_version_mismatch_rejected(void)
{
	TEST("version mismatch is rejected");

	int fds[2];
	ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair failed");

	struct jobd_msg_header hdr = {
		.magic       = JOBD_PROTO_MAGIC,
		.version     = JOBD_PROTO_VERSION + 1,
		.type        = JOBD_MSG_RUN,
		.payload_len = 0,
		.request_id  = 1,
	};
	jobd_send_msg(fds[0], &hdr, NULL);

	struct jobd_msg_header rhdr;
	uint8_t buf[16];
	ASSERT(jobd_recv_msg(fds[1], &rhdr, buf, sizeof(buf), NULL) == -3,
	       "should reject a version mismatch");

	close(fds[0]);
	close(fds[1]);
	PASS();
}

static void test_bad_fd(void)
{
	TEST("short read on a bad descriptor fails");
	ASSERT(jobd_read_full(-1, NULL, 16) == -1, "should fail on a bad fd");
	PASS();
}

int main(void)
{
	printf("=== protocol tests ===\n\n");

	test_magic();
	test_header_wire_size();
	test_codec_roundtrip();
	test_codec_is_little_endian();
	test_writer_refuses_overflow();
	test_reader_refuses_short_read();
	test_str_does_not_truncate();
	test_count_limit();
	test_send_recv_roundtrip();
	test_response_roundtrip();
	test_oversized_payload_rejected();
	test_version_mismatch_rejected();
	test_bad_fd();

	TEST_SUMMARY();
}
