#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include "jobd.h"
#include "testutil.h"

static void fill_job(struct job *job)
{
	char err[256];

	job_set_defaults(job);
	snprintf(job->id, sizeof(job->id), "roundtrip-1");
	job->memory_max = 2147483648ULL;
	job->pids_max   = 64;
	job->timeout_ms = 12345;
	job->fanotify_mode = JOBD_FANOTIFY_DENY;
	job->iouring_enabled = 1;

	snprintf(job->ro_paths[0], JOBD_MAX_PATH_LEN, "/usr");
	job->ro_count = 1;
	snprintf(job->rw_paths[0], JOBD_MAX_PATH_LEN, "/workspace");
	job->rw_count = 1;
	snprintf(job->canaries[0], JOBD_MAX_PATH_LEN, "/workspace/.secret");
	job->canary_count = 1;
	snprintf(job->memfd_inputs[0].name, JOBD_MAX_PATH_LEN, "model");
	snprintf(job->memfd_inputs[0].path, JOBD_MAX_PATH_LEN, "/srv/model.bin");
	job->memfd_input_count = 1;

	job_add_arg(job, "/usr/bin/python3", err, sizeof(err));
	job_add_arg(job, "/workspace/job.py", err, sizeof(err));
	job_add_env(job, "MODEL=small", err, sizeof(err));
}

static void test_roundtrip(void)
{
	TEST("run request survives a round trip");

	struct job in, out;
	char err[512];
	fill_job(&in);

	uint8_t *buf = malloc(JOBD_MAX_PAYLOAD);
	ASSERT(buf != NULL, "allocation failed");

	size_t len = 0;
	int rc = jobd_encode_run_request(&in, buf, JOBD_MAX_PAYLOAD, &len,
	                                   err, sizeof(err));
	ASSERT(rc == 0, err);

	rc = jobd_decode_run_request(buf, len, &out, err, sizeof(err));
	free(buf);
	ASSERT(rc == 0, err);

	ASSERT(strcmp(out.id, in.id) == 0, "job id mismatch");
	ASSERT(out.memory_max == in.memory_max, "memory_max mismatch");
	ASSERT(out.pids_max == in.pids_max, "pids_max mismatch");
	ASSERT(out.timeout_ms == in.timeout_ms, "timeout mismatch");
	ASSERT(out.fanotify_mode == in.fanotify_mode, "fanotify mode mismatch");
	ASSERT(out.iouring_enabled == in.iouring_enabled, "iouring mismatch");
	ASSERT(out.ro_count == 1 && strcmp(out.ro_paths[0], "/usr") == 0,
	       "ro path mismatch");
	ASSERT(out.rw_count == 1 && strcmp(out.rw_paths[0], "/workspace") == 0,
	       "rw path mismatch");
	ASSERT(out.canary_count == 1, "canary mismatch");
	ASSERT(out.memfd_input_count == 1 &&
	       strcmp(out.memfd_inputs[0].name, "model") == 0,
	       "memfd input mismatch");
	ASSERT(out.argc == 2, "argc mismatch");
	ASSERT(out.envc == 1, "envc mismatch");
	PASS();
}

static void test_argv_boundaries_preserved(void)
{
	TEST("arguments containing spaces survive intact");

	struct job in, out;
	char err[512];

	job_set_defaults(&in);
	snprintf(in.id, sizeof(in.id), "spaces");
	job_add_arg(&in, "/bin/echo", err, sizeof(err));
	job_add_arg(&in, "hello world", err, sizeof(err));
	job_add_arg(&in, "  leading and trailing  ", err, sizeof(err));
	job_add_arg(&in, "tab\tseparated", err, sizeof(err));

	uint8_t *buf = malloc(JOBD_MAX_PAYLOAD);
	ASSERT(buf != NULL, "allocation failed");

	size_t len = 0;
	ASSERT(jobd_encode_run_request(&in, buf, JOBD_MAX_PAYLOAD, &len,
	                                 err, sizeof(err)) == 0, err);
	int rc = jobd_decode_run_request(buf, len, &out, err, sizeof(err));
	free(buf);
	ASSERT(rc == 0, err);

	char *av[JOBD_MAX_ARGV + 1];
	int n = job_argv(&out, av, JOBD_MAX_ARGV + 1);
	ASSERT(n == 4, "argument count changed");
	ASSERT(strcmp(av[0], "/bin/echo") == 0, "argv[0] mismatch");
	ASSERT(strcmp(av[1], "hello world") == 0,
	       "an argument with a space was split");
	ASSERT(strcmp(av[2], "  leading and trailing  ") == 0,
	       "surrounding spaces were lost");
	ASSERT(strcmp(av[3], "tab\tseparated") == 0, "tab argument mangled");
	ASSERT(av[4] == NULL, "vector must be NULL terminated");
	PASS();
}

static void test_oversized_count_rejected(void)
{
	TEST("oversized element count is rejected before copying");

	uint8_t *buf = calloc(1, JOBD_MAX_PAYLOAD);
	ASSERT(buf != NULL, "allocation failed");

	struct agd_wr w;
	agd_wr_init(&w, buf, JOBD_MAX_PAYLOAD);

	for (int i = 0; i < 6; i++)
		agd_wr_u64(&w, 0);
	for (int i = 0; i < 3; i++)
		agd_wr_u32(&w, 1);
	for (int i = 0; i < 4; i++)
		agd_wr_u8(&w, 0);
	agd_wr_str(&w, "overflow");

	agd_wr_u32(&w, 1023);
	for (int i = 0; i < 1023; i++)
		agd_wr_str(&w, "/aaaaaaaaaaaaaaaa");

	struct job job;
	char err[512];
	int rc = jobd_decode_run_request(buf, w.len, &job, err, sizeof(err));
	free(buf);

	ASSERT(rc != 0, "decoder accepted an oversized layer count");
	PASS();
}

static void test_integer_overflow_count_rejected(void)
{
	TEST("count chosen to wrap 32-bit arithmetic is rejected");

	uint8_t *buf = calloc(1, JOBD_MAX_PAYLOAD);
	ASSERT(buf != NULL, "allocation failed");

	struct agd_wr w;
	agd_wr_init(&w, buf, JOBD_MAX_PAYLOAD);

	for (int i = 0; i < 6; i++)
		agd_wr_u64(&w, 0);
	for (int i = 0; i < 3; i++)
		agd_wr_u32(&w, 1);
	for (int i = 0; i < 4; i++)
		agd_wr_u8(&w, 0);
	agd_wr_str(&w, "wrap");

	agd_wr_u32(&w, 16777216u);

	struct job job;
	char err[512];
	int rc = jobd_decode_run_request(buf, w.len, &job, err, sizeof(err));
	free(buf);

	ASSERT(rc != 0, "decoder accepted a wrapping count");
	PASS();
}

static void test_oversized_string_rejected(void)
{
	TEST("a string longer than its destination is rejected");

	uint8_t *buf = calloc(1, JOBD_MAX_PAYLOAD);
	ASSERT(buf != NULL, "allocation failed");

	struct agd_wr w;
	agd_wr_init(&w, buf, JOBD_MAX_PAYLOAD);

	for (int i = 0; i < 6; i++)
		agd_wr_u64(&w, 0);
	for (int i = 0; i < 3; i++)
		agd_wr_u32(&w, 1);
	for (int i = 0; i < 4; i++)
		agd_wr_u8(&w, 0);

	char big[4096];
	memset(big, 'a', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	agd_wr_str(&w, big);

	struct job job;
	char err[512];
	int rc = jobd_decode_run_request(buf, w.len, &job, err, sizeof(err));
	free(buf);

	ASSERT(rc != 0, "decoder accepted an oversized job ID");
	PASS();
}

static void test_truncated_payload_rejected(void)
{
	TEST("a truncated payload is rejected");

	struct job in, out;
	char err[512];
	fill_job(&in);

	uint8_t *buf = malloc(JOBD_MAX_PAYLOAD);
	ASSERT(buf != NULL, "allocation failed");

	size_t len = 0;
	ASSERT(jobd_encode_run_request(&in, buf, JOBD_MAX_PAYLOAD, &len,
	                                 err, sizeof(err)) == 0, err);

	int all_rejected = 1;
	for (size_t cut = 1; cut < len; cut += 7) {
		if (jobd_decode_run_request(buf, cut, &out,
		                              err, sizeof(err)) == 0) {
			all_rejected = 0;
			break;
		}
	}
	free(buf);

	ASSERT(all_rejected, "a truncated request was accepted");
	PASS();
}

static void test_trailing_bytes_rejected(void)
{
	TEST("trailing bytes are rejected");

	struct job in, out;
	char err[512];
	fill_job(&in);

	uint8_t *buf = calloc(1, JOBD_MAX_PAYLOAD);
	ASSERT(buf != NULL, "allocation failed");

	size_t len = 0;
	ASSERT(jobd_encode_run_request(&in, buf, JOBD_MAX_PAYLOAD, &len,
	                                 err, sizeof(err)) == 0, err);

	int rc = jobd_decode_run_request(buf, len + 8, &out, err, sizeof(err));
	free(buf);

	ASSERT(rc != 0, "decoder ignored trailing bytes");
	PASS();
}

static void test_embedded_nul_rejected(void)
{
	TEST("a string with an embedded NUL is rejected");

	uint8_t *buf = calloc(1, JOBD_MAX_PAYLOAD);
	ASSERT(buf != NULL, "allocation failed");

	struct agd_wr w;
	agd_wr_init(&w, buf, JOBD_MAX_PAYLOAD);

	for (int i = 0; i < 6; i++)
		agd_wr_u64(&w, 0);
	for (int i = 0; i < 3; i++)
		agd_wr_u32(&w, 1);
	for (int i = 0; i < 4; i++)
		agd_wr_u8(&w, 0);

	agd_wr_u32(&w, 5);
	agd_wr_bytes(&w, "ab\0cd", 5);

	struct job job;
	char err[512];
	int rc = jobd_decode_run_request(buf, w.len, &job, err, sizeof(err));
	free(buf);

	ASSERT(rc != 0, "decoder accepted an embedded NUL");
	PASS();
}

int main(void)
{
	printf("=== run request codec tests ===\n\n");

	test_roundtrip();
	test_argv_boundaries_preserved();
	test_oversized_count_rejected();
	test_integer_overflow_count_rejected();
	test_oversized_string_rejected();
	test_truncated_payload_rejected();
	test_trailing_bytes_rejected();
	test_embedded_nul_rejected();

	TEST_SUMMARY();
}
