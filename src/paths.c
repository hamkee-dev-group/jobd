#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "jobd.h"

static int g_debug;

void jobd_log_set_debug(int on) { g_debug = on; }

static uint64_t now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void jobd_log(const char *fmt, ...)
{
	char stamp[32];
	struct timespec ts;
	struct tm tm;

	if (clock_gettime(CLOCK_REALTIME, &ts) == 0 &&
	    gmtime_r(&ts.tv_sec, &tm))
		strftime(stamp, sizeof(stamp), "%Y-%m-%dT%H:%M:%SZ", &tm);
	else
		snprintf(stamp, sizeof(stamp), "-");

	fprintf(stderr, "%s jobd: ", stamp);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fputc('\n', stderr);
	fflush(stderr);
}

void jobd_log_event(const char *job_id, const char *component,
                      const char *event, const char *extra)
{
	char line[2048];
	struct agd_buf b;

	agd_buf_init(&b, line, sizeof(line));
	agd_buf_addf(&b, "{\"ts_ns\":%llu,\"job_id\":\"",
	             (unsigned long long)now_ns());
	agd_buf_add_json(&b, job_id ? job_id : "");
	agd_buf_adds(&b, "\",\"component\":\"");
	agd_buf_add_json(&b, component ? component : "");
	agd_buf_adds(&b, "\",\"event\":\"");
	agd_buf_add_json(&b, event ? event : "");
	agd_buf_adds(&b, "\",\"extra\":\"");
	agd_buf_add_json(&b, extra ? extra : "");
	agd_buf_adds(&b, "\"}");

	fprintf(stderr, "%s\n", line);
	fflush(stderr);

	if (g_debug)
		fflush(stderr);
}
