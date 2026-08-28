#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include "jobd.h"

void agd_wr_init(struct agd_wr *w, uint8_t *buf, size_t cap)
{
	w->buf = buf;
	w->cap = cap;
	w->len = 0;
	w->err = 0;
}

int agd_wr_ok(const struct agd_wr *w) { return w->err == 0; }

static int wr_room(struct agd_wr *w, size_t n)
{
	if (w->err)
		return 0;
	if (n > w->cap - w->len) {
		w->err = 1;
		return 0;
	}
	return 1;
}

int agd_wr_u8(struct agd_wr *w, uint8_t v)
{
	if (!wr_room(w, 1))
		return -1;
	w->buf[w->len++] = v;
	return 0;
}

int agd_wr_u16(struct agd_wr *w, uint16_t v)
{
	if (!wr_room(w, 2))
		return -1;
	w->buf[w->len++] = (uint8_t)(v & 0xff);
	w->buf[w->len++] = (uint8_t)((v >> 8) & 0xff);
	return 0;
}

int agd_wr_u32(struct agd_wr *w, uint32_t v)
{
	if (!wr_room(w, 4))
		return -1;
	for (int i = 0; i < 4; i++)
		w->buf[w->len++] = (uint8_t)((v >> (8 * i)) & 0xff);
	return 0;
}

int agd_wr_u64(struct agd_wr *w, uint64_t v)
{
	if (!wr_room(w, 8))
		return -1;
	for (int i = 0; i < 8; i++)
		w->buf[w->len++] = (uint8_t)((v >> (8 * i)) & 0xff);
	return 0;
}

int agd_wr_bytes(struct agd_wr *w, const void *p, size_t n)
{
	if (!wr_room(w, n))
		return -1;
	memcpy(w->buf + w->len, p, n);
	w->len += n;
	return 0;
}

int agd_wr_str(struct agd_wr *w, const char *s)
{
	size_t n = s ? strlen(s) : 0;
	if (n > 0xFFFFFFFFu) {
		w->err = 1;
		return -1;
	}
	if (agd_wr_u32(w, (uint32_t)n) != 0)
		return -1;
	if (n == 0)
		return 0;
	return agd_wr_bytes(w, s, n);
}

void agd_rd_init(struct agd_rd *r, const uint8_t *buf, size_t len)
{
	r->buf = buf;
	r->len = len;
	r->off = 0;
	r->err = 0;
}

int agd_rd_ok(const struct agd_rd *r) { return r->err == 0; }

static int rd_room(struct agd_rd *r, size_t n)
{
	if (r->err)
		return 0;
	if (n > r->len - r->off) {
		r->err = 1;
		return 0;
	}
	return 1;
}

int agd_rd_u8(struct agd_rd *r, uint8_t *v)
{
	if (!rd_room(r, 1))
		return -1;
	*v = r->buf[r->off++];
	return 0;
}

int agd_rd_u16(struct agd_rd *r, uint16_t *v)
{
	if (!rd_room(r, 2))
		return -1;
	*v = (uint16_t)(r->buf[r->off] | ((uint16_t)r->buf[r->off + 1] << 8));
	r->off += 2;
	return 0;
}

int agd_rd_u32(struct agd_rd *r, uint32_t *v)
{
	if (!rd_room(r, 4))
		return -1;
	uint32_t out = 0;
	for (int i = 0; i < 4; i++)
		out |= (uint32_t)r->buf[r->off + i] << (8 * i);
	r->off += 4;
	*v = out;
	return 0;
}

int agd_rd_u64(struct agd_rd *r, uint64_t *v)
{
	if (!rd_room(r, 8))
		return -1;
	uint64_t out = 0;
	for (int i = 0; i < 8; i++)
		out |= (uint64_t)r->buf[r->off + i] << (8 * i);
	r->off += 8;
	*v = out;
	return 0;
}

int agd_rd_bytes(struct agd_rd *r, void *p, size_t n)
{
	if (!rd_room(r, n))
		return -1;
	memcpy(p, r->buf + r->off, n);
	r->off += n;
	return 0;
}

int agd_rd_str(struct agd_rd *r, char *dst, size_t dst_sz)
{
	uint32_t n = 0;
	if (agd_rd_u32(r, &n) != 0)
		return -1;

	if ((uint64_t)n >= (uint64_t)dst_sz) {
		r->err = 1;
		return -1;
	}
	if (!rd_room(r, n))
		return -1;

	memcpy(dst, r->buf + r->off, n);
	dst[n] = '\0';
	r->off += n;

	if (strlen(dst) != n) {
		r->err = 1;
		return -1;
	}
	return 0;
}

int agd_rd_count(struct agd_rd *r, uint32_t max, uint32_t *out)
{
	uint32_t n = 0;
	if (agd_rd_u32(r, &n) != 0)
		return -1;
	if (n > max) {
		r->err = 1;
		return -1;
	}
	*out = n;
	return 0;
}

int jobd_read_full(int fd, void *buf, size_t sz)
{
	uint8_t *p = buf;
	size_t remaining = sz;
	while (remaining > 0) {
		ssize_t n = read(fd, p, remaining);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += (size_t)n;
		remaining -= (size_t)n;
	}
	return 0;
}

int jobd_write_full(int fd, const void *buf, size_t sz)
{
	const uint8_t *p = buf;
	size_t remaining = sz;
	while (remaining > 0) {
		ssize_t n = write(fd, p, remaining);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;
		p += (size_t)n;
		remaining -= (size_t)n;
	}
	return 0;
}

int jobd_recv_msg(int fd, struct jobd_msg_header *hdr,
                    uint8_t *buf, size_t buf_sz, size_t *received)
{
	uint8_t raw[JOBD_HDR_WIRE_SIZE];
	if (jobd_read_full(fd, raw, sizeof(raw)) != 0)
		return -1;

	struct agd_rd r;
	agd_rd_init(&r, raw, sizeof(raw));
	agd_rd_u32(&r, &hdr->magic);
	agd_rd_u16(&r, &hdr->version);
	agd_rd_u16(&r, &hdr->type);
	agd_rd_u32(&r, &hdr->payload_len);
	agd_rd_u64(&r, &hdr->request_id);
	if (!agd_rd_ok(&r))
		return -1;

	if (hdr->magic != JOBD_PROTO_MAGIC)
		return -2;
	if (hdr->version != JOBD_PROTO_VERSION)
		return -3;
	if (hdr->payload_len > JOBD_MAX_PAYLOAD || hdr->payload_len > buf_sz)
		return -4;

	if (hdr->payload_len > 0) {
		if (jobd_read_full(fd, buf, hdr->payload_len) != 0)
			return -5;
	}

	if (received)
		*received = hdr->payload_len;
	return 0;
}

int jobd_send_msg(int fd, const struct jobd_msg_header *hdr,
                    const uint8_t *payload)
{
	uint8_t raw[JOBD_HDR_WIRE_SIZE];
	struct agd_wr w;

	agd_wr_init(&w, raw, sizeof(raw));
	agd_wr_u32(&w, hdr->magic);
	agd_wr_u16(&w, hdr->version);
	agd_wr_u16(&w, hdr->type);
	agd_wr_u32(&w, hdr->payload_len);
	agd_wr_u64(&w, hdr->request_id);
	if (!agd_wr_ok(&w))
		return -1;

	if (jobd_write_full(fd, raw, w.len) != 0)
		return -1;
	if (hdr->payload_len > 0 && payload) {
		if (jobd_write_full(fd, payload, hdr->payload_len) != 0)
			return -2;
	}
	return 0;
}

int jobd_send_response(int fd, uint64_t request_id, int status,
                         const uint8_t *data, uint32_t data_len)
{
	if (!data)
		data_len = 0;
	if (data_len > JOBD_MAX_PAYLOAD - JOBD_RESP_WIRE_SIZE)
		data_len = JOBD_MAX_PAYLOAD - JOBD_RESP_WIRE_SIZE;

	struct jobd_msg_header hdr = {
		.magic       = JOBD_PROTO_MAGIC,
		.version     = JOBD_PROTO_VERSION,
		.type        = JOBD_MSG_RESPONSE,
		.payload_len = JOBD_RESP_WIRE_SIZE + data_len,
		.request_id  = request_id,
	};

	uint8_t raw[JOBD_HDR_WIRE_SIZE];
	struct agd_wr w;
	agd_wr_init(&w, raw, sizeof(raw));
	agd_wr_u32(&w, hdr.magic);
	agd_wr_u16(&w, hdr.version);
	agd_wr_u16(&w, hdr.type);
	agd_wr_u32(&w, hdr.payload_len);
	agd_wr_u64(&w, hdr.request_id);
	if (!agd_wr_ok(&w))
		return -1;
	if (jobd_write_full(fd, raw, w.len) != 0)
		return -1;

	uint8_t rb[JOBD_RESP_WIRE_SIZE];
	agd_wr_init(&w, rb, sizeof(rb));
	agd_wr_u32(&w, (uint32_t)status);
	agd_wr_u32(&w, data_len);
	agd_wr_u64(&w, 0);
	if (!agd_wr_ok(&w))
		return -1;
	if (jobd_write_full(fd, rb, w.len) != 0)
		return -1;

	if (data_len > 0)
		return jobd_write_full(fd, data, data_len) == 0 ? 0 : -2;
	return 0;
}

int jobd_parse_response(const uint8_t *buf, size_t len,
                          struct jobd_response *resp,
                          const uint8_t **data)
{
	struct agd_rd r;
	uint32_t status = 0;

	agd_rd_init(&r, buf, len);
	agd_rd_u32(&r, &status);
	agd_rd_u32(&r, &resp->result_len);
	uint64_t reserved = 0;
	agd_rd_u64(&r, &reserved);
	if (!agd_rd_ok(&r))
		return -1;

	resp->status = (int32_t)status;
	memset(resp->reserved, 0, sizeof(resp->reserved));

	if ((uint64_t)resp->result_len > (uint64_t)(len - r.off))
		return -1;

	if (data)
		*data = buf + r.off;
	return 0;
}
