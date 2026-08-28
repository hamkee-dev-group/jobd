#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "jobd_buf.h"

void agd_buf_init(struct agd_buf *b, char *data, size_t cap)
{
	b->data      = data;
	b->cap       = cap;
	b->len       = 0;
	b->truncated = 0;
	if (cap > 0)
		data[0] = '\0';
}

size_t agd_buf_len(const struct agd_buf *b)      { return b->len; }
int    agd_buf_truncated(const struct agd_buf *b) { return b->truncated; }

void agd_buf_vaddf(struct agd_buf *b, const char *fmt, va_list ap)
{
	if (b->cap == 0 || b->len >= b->cap - 1) {
		b->truncated = 1;
		return;
	}

	size_t avail = b->cap - b->len;
	int n = vsnprintf(b->data + b->len, avail, fmt, ap);
	if (n < 0) {
		b->truncated = 1;
		b->data[b->len] = '\0';
		return;
	}

	if ((size_t)n >= avail) {

		b->len       = b->cap - 1;
		b->truncated = 1;
	} else {
		b->len += (size_t)n;
	}
	b->data[b->len] = '\0';
}

void agd_buf_addf(struct agd_buf *b, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	agd_buf_vaddf(b, fmt, ap);
	va_end(ap);
}

void agd_buf_addch(struct agd_buf *b, char c)
{
	if (b->cap == 0 || b->len >= b->cap - 1) {
		b->truncated = 1;
		return;
	}
	b->data[b->len++] = c;
	b->data[b->len]   = '\0';
}

void agd_buf_adds(struct agd_buf *b, const char *s)
{
	if (!s)
		return;
	for (; *s; s++) {
		if (b->cap == 0 || b->len >= b->cap - 1) {
			b->truncated = 1;
			return;
		}
		b->data[b->len++] = *s;
	}
	if (b->cap > 0)
		b->data[b->len] = '\0';
}

static void add_escaped(struct agd_buf *b, const char *s, int toml)
{
	if (!s)
		return;

	for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
		switch (*p) {
		case '"':  agd_buf_adds(b, "\\\""); continue;
		case '\\': agd_buf_adds(b, "\\\\"); continue;
		case '\b': agd_buf_adds(b, "\\b");  continue;
		case '\f': agd_buf_adds(b, "\\f");  continue;
		case '\n': agd_buf_adds(b, "\\n");  continue;
		case '\r': agd_buf_adds(b, "\\r");  continue;
		case '\t': agd_buf_adds(b, "\\t");  continue;
		default:
			break;
		}

		if (*p < 0x20 || *p == 0x7f) {

			agd_buf_addf(b, "\\u%04x", (unsigned)*p);
			continue;
		}

		agd_buf_addch(b, (char)*p);
	}

	(void)toml;
}

void agd_buf_add_toml(struct agd_buf *b, const char *s) { add_escaped(b, s, 1); }
void agd_buf_add_json(struct agd_buf *b, const char *s) { add_escaped(b, s, 0); }
