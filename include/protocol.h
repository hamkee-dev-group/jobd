#ifndef JOBD_PROTOCOL_H
#define JOBD_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define JOBD_PROTO_MAGIC     0x4A424431u
#define JOBD_PROTO_VERSION   3

#define JOBD_MAX_PAYLOAD     (256 * 1024)

#define JOBD_MAX_ARGV        64u
#define JOBD_MAX_ARG_LEN     4096u
#define JOBD_ARGV_BYTES      (64 * 1024)
#define JOBD_MAX_ENV_COUNT   64u
#define JOBD_MAX_ENV_LEN     4096u
#define JOBD_ENV_BYTES       (16 * 1024)
#define JOBD_MAX_PATH_COUNT  64u
#define JOBD_MAX_PATH_LEN    256u

#define JOBD_PATH_LEN_LONG   1024
#define JOBD_MAX_MEMFD_INPUT 32u
#define JOBD_MAX_LAYERS      8u
#define JOBD_MAX_CANARIES    16u
#define JOBD_MAX_JOB_ID      64u

enum jobd_msg_type {
	JOBD_MSG_RUN      = 1,
	JOBD_MSG_INSPECT  = 2,
	JOBD_MSG_WAIT     = 3,
	JOBD_MSG_LOGS     = 4,
	JOBD_MSG_KILL     = 5,
	JOBD_MSG_LIST     = 6,
	JOBD_MSG_CLEANUP  = 7,
	JOBD_MSG_DOCTOR   = 8,
	JOBD_MSG_RESPONSE = 0x8000,
};

#define JOBD_HDR_WIRE_SIZE 20

struct jobd_msg_header {
	uint32_t magic;
	uint16_t version;
	uint16_t type;
	uint32_t payload_len;
	uint64_t request_id;
};

#define JOBD_RESP_WIRE_SIZE 16

struct jobd_response {
	int32_t  status;
	uint32_t result_len;
	uint8_t  reserved[8];
};

enum jobd_status {
	JOBD_STATUS_OK            = 0,
	JOBD_STATUS_ERR_PROTOCOL  = 1,
	JOBD_STATUS_ERR_VALIDATE  = 2,
	JOBD_STATUS_ERR_PREFLIGHT = 3,
	JOBD_STATUS_ERR_SETUP     = 4,
	JOBD_STATUS_ERR_INTERNAL  = 5,
	JOBD_STATUS_ERR_NOTFOUND  = 6,
	JOBD_STATUS_ERR_CONFLICT  = 7,
	JOBD_STATUS_ERR_PERM      = 8,
};

enum jobd_network_mode {
	JOBD_NETWORK_NONE     = 0,

	JOBD_NETWORK_BROKERED = 1,
};

#define JOBD_MAX_ALLOW_NET   32u
#define JOBD_MAX_ALLOW_LEN   256u

#define JOBD_BROKER_PORT     1080

enum jobd_fanotify_mode {
	JOBD_FANOTIFY_OFF     = 0,
	JOBD_FANOTIFY_OBSERVE = 1,
	JOBD_FANOTIFY_DENY    = 2,
};

struct agd_wr {
	uint8_t *buf;
	size_t   cap;
	size_t   len;
	int      err;
};

struct agd_rd {
	const uint8_t *buf;
	size_t         len;
	size_t         off;
	int            err;
};

void agd_wr_init(struct agd_wr *w, uint8_t *buf, size_t cap);
int  agd_wr_u8(struct agd_wr *w, uint8_t v);
int  agd_wr_u16(struct agd_wr *w, uint16_t v);
int  agd_wr_u32(struct agd_wr *w, uint32_t v);
int  agd_wr_u64(struct agd_wr *w, uint64_t v);
int  agd_wr_bytes(struct agd_wr *w, const void *p, size_t n);
int  agd_wr_str(struct agd_wr *w, const char *s);
int  agd_wr_ok(const struct agd_wr *w);

void agd_rd_init(struct agd_rd *r, const uint8_t *buf, size_t len);
int  agd_rd_u8(struct agd_rd *r, uint8_t *v);
int  agd_rd_u16(struct agd_rd *r, uint16_t *v);
int  agd_rd_u32(struct agd_rd *r, uint32_t *v);
int  agd_rd_u64(struct agd_rd *r, uint64_t *v);
int  agd_rd_bytes(struct agd_rd *r, void *p, size_t n);

int  agd_rd_str(struct agd_rd *r, char *dst, size_t dst_sz);

int  agd_rd_count(struct agd_rd *r, uint32_t max, uint32_t *out);
int  agd_rd_ok(const struct agd_rd *r);

#endif
