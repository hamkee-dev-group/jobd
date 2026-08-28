#ifndef JOBD_BUF_H
#define JOBD_BUF_H

#include <stdarg.h>
#include <stddef.h>

struct agd_buf {
	char  *data;
	size_t cap;
	size_t len;
	int    truncated;
};

void   agd_buf_init(struct agd_buf *b, char *data, size_t cap);
void   agd_buf_addf(struct agd_buf *b, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
void   agd_buf_vaddf(struct agd_buf *b, const char *fmt, va_list ap);
void   agd_buf_adds(struct agd_buf *b, const char *s);
void   agd_buf_addch(struct agd_buf *b, char c);

void   agd_buf_add_toml(struct agd_buf *b, const char *s);
void   agd_buf_add_json(struct agd_buf *b, const char *s);

size_t agd_buf_len(const struct agd_buf *b);
int    agd_buf_truncated(const struct agd_buf *b);

#endif
