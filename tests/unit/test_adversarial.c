#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "jobd.h"
#include "testutil.h"

static void test_job_id_path_traversal(void)
{
	TEST("job IDs rejecting path traversal");

	char err[256];
	const char *bad[] = {
		"../etc", "dir/../etc", "/etc", ".", "..", "a/b", "./x", NULL
	};

	for (int i = 0; bad[i]; i++) {
		if (job_id_validate(bad[i], err, sizeof(err)) == 0) {
			FAIL(bad[i]);
			return;
		}
	}
	PASS();
}

static void test_job_id_special_chars(void)
{
	TEST("job IDs rejecting shell and control characters");

	char err[256];
	const char *bad[] = {
		"job\nid", "job\tid", "job\rid", "job\vid",
		"hello world", "job;id", "job|id", "job&id",
		"job$id", "job`id`", "job(id)", "job[id]",
		"job{id}", "job<id>", "job#id", "job!id",
		"job@id", "job^id", "job~id", "job%id",
		"job\"id", "job'id", "job\\id", "job\xffid",
		NULL
	};

	for (int i = 0; bad[i]; i++) {
		if (job_id_validate(bad[i], err, sizeof(err)) == 0) {
			FAIL(bad[i]);
			return;
		}
	}
	PASS();
}

static void test_job_id_length(void)
{
	TEST("job ID length bounds");

	char err[256];
	char exact[JOBD_MAX_JOB_ID + 1];
	memset(exact, 'a', JOBD_MAX_JOB_ID);
	exact[JOBD_MAX_JOB_ID] = '\0';
	ASSERT(job_id_validate(exact, err, sizeof(err)) == 0,
	       "the maximum length should be accepted");

	char over[JOBD_MAX_JOB_ID + 2];
	memset(over, 'a', JOBD_MAX_JOB_ID + 1);
	over[JOBD_MAX_JOB_ID + 1] = '\0';
	ASSERT(job_id_validate(over, err, sizeof(err)) != 0,
	       "one byte over the maximum should be rejected");

	ASSERT(job_id_validate("", err, sizeof(err)) != 0,
	       "an empty ID should be rejected");
	ASSERT(job_id_validate(NULL, err, sizeof(err)) != 0,
	       "a NULL ID should be rejected");
	PASS();
}

static void test_policy_injection_is_escaped(void)
{
	TEST("policy injection through a path is neutralised");

	char store[512];
	struct agd_buf b;
	agd_buf_init(&b, store, sizeof(store));

	agd_buf_adds(&b, "  path = \"");
	agd_buf_add_toml(&b,
	                 "/workspace\"]\n\n  [[fs_layer.rule]]\n"
	                 "  path = \"/\"\n  allowed_access = [\"write_file\"");
	agd_buf_adds(&b, "\"\n");

	int rule_count = 0;
	for (const char *p = store; (p = strstr(p, "path = \"")); p += 8)
		rule_count++;

	ASSERT(rule_count == 1, "escaping should leave exactly one rule");
	ASSERT(strchr(store + 10, '\n') == store + strlen(store) - 1,
	       "no embedded newline should survive");
	PASS();
}

static void test_unterminated_job_id_payload(void)
{
	TEST("job ID payload without a terminator is bounded");

	char jid[JOBD_MAX_JOB_ID + 1];
	uint8_t payload[16];
	memset(payload, 'a', sizeof(payload));

	size_t len = sizeof(payload);
	ASSERT(len < sizeof(jid), "test setup");

	memcpy(jid, payload, len);
	jid[len] = '\0';

	char err[256];
	ASSERT(strlen(jid) == len, "length must come from the header");
	ASSERT(job_id_validate(jid, err, sizeof(err)) == 0,
	       "a bounded copy should validate");
	PASS();
}

static void test_oversized_protocol_payload(void)
{
	TEST("oversized payload indicator is rejected");

	int fds[2];
	ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");

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
	       "should reject a huge payload_len");

	close(fds[0]);
	close(fds[1]);
	PASS();
}

static void test_hostile_run_request(void)
{
	TEST("hostile run request is rejected");

	uint8_t *buf = calloc(1, JOBD_MAX_PAYLOAD);
	ASSERT(buf != NULL, "allocation");

	const uint32_t counts[] = { 1023, 65535, 16777216u, 0xFFFFFFFFu };

	for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++) {
		struct agd_wr w;
		agd_wr_init(&w, buf, JOBD_MAX_PAYLOAD);

		for (int i = 0; i < 6; i++)
			agd_wr_u64(&w, 0);
		for (int i = 0; i < 3; i++)
			agd_wr_u32(&w, 1);
		for (int i = 0; i < 4; i++)
			agd_wr_u8(&w, 0);
		agd_wr_str(&w, "hostile");
		agd_wr_u32(&w, counts[c]);

		for (int i = 0; i < 200 && agd_wr_ok(&w); i++)
			agd_wr_str(&w, "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

		struct job job;
		char err[512];
		if (jobd_decode_run_request(buf, w.len, &job,
		                              err, sizeof(err)) == 0) {
			free(buf);
			FAIL("decoder accepted an oversized count");
			return;
		}
	}

	free(buf);
	PASS();
}

static void test_dryrun_output_is_bounded(void)
{
	TEST("dry-run output stays inside a small buffer");

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "bounded");
	job_add_arg(&job, "/bin/true", err, sizeof(err));

	for (uint32_t i = 0; i < JOBD_MAX_PATH_COUNT; i++) {
		snprintf(job.ro_paths[i], JOBD_MAX_PATH_LEN,
		         "/read/only/path/number/%u/with/some/extra/length", i);
		snprintf(job.rw_paths[i], JOBD_MAX_PATH_LEN,
		         "/read/write/path/number/%u/with/some/extra/length", i);
	}
	job.ro_count = JOBD_MAX_PATH_COUNT;
	job.rw_count = JOBD_MAX_PATH_COUNT;

	char small[512];
	char canary[64];
	memset(canary, 0x5a, sizeof(canary));

	ASSERT(jobd_policy_plan_dryrun(&job, small, sizeof(small)) == 0,
	       "dry run should succeed");
	ASSERT(strlen(small) < sizeof(small), "output must stay in bounds");

	for (size_t i = 0; i < sizeof(canary); i++)
		ASSERT(canary[i] == 0x5a, "dry run wrote past its buffer");
	PASS();
}

static void test_doctor_output_is_bounded(void)
{
	TEST("doctor output stays inside a small buffer");

	char small[256];
	char canary[64];
	memset(canary, 0x5a, sizeof(canary));

	ASSERT(jobd_doctor(small, sizeof(small)) == 0, "doctor should succeed");
	ASSERT(strlen(small) < sizeof(small), "output must stay in bounds");

	for (size_t i = 0; i < sizeof(canary); i++)
		ASSERT(canary[i] == 0x5a, "doctor wrote past its buffer");
	PASS();
}

static void test_env_is_not_inherited(void)
{
	TEST("the workload environment is not inherited from the host");

	setenv("SECRET_TOKEN", "must-not-leak", 1);
	setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak", 1);

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "envtest");
	job_add_arg(&job, "/bin/true", err, sizeof(err));

	char  buf[JOBD_ENV_BYTES + 2048];
	char *env[JOBD_MAX_ENV_COUNT + 16];
	int n = job_build_launch_env(&job, buf, sizeof(buf), env,
	                               JOBD_MAX_ENV_COUNT + 16,
	                               err, sizeof(err));
	ASSERT(n > 0, err);

	for (int i = 0; i < n; i++) {
		if (strstr(env[i], "must-not-leak")) {
			FAIL("a host environment variable leaked");
			return;
		}
	}
	PASS();
}

static void test_env_override(void)
{
	TEST("a client entry overrides the matching default");

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "envover");
	job_add_arg(&job, "/bin/true", err, sizeof(err));
	job_add_env(&job, "PATH=/custom/bin", err, sizeof(err));

	char  buf[JOBD_ENV_BYTES + 2048];
	char *env[JOBD_MAX_ENV_COUNT + 16];
	int n = job_build_launch_env(&job, buf, sizeof(buf), env,
	                               JOBD_MAX_ENV_COUNT + 16,
	                               err, sizeof(err));
	ASSERT(n > 0, err);

	int path_count = 0;
	for (int i = 0; i < n; i++) {
		if (strncmp(env[i], "PATH=", 5) == 0) {
			path_count++;
			ASSERT(strcmp(env[i], "PATH=/custom/bin") == 0,
			       "the override should win");
		}
	}
	ASSERT(path_count == 1, "PATH should appear exactly once");
	PASS();
}

int main(void)
{
	printf("=== adversarial / edge-case tests ===\n\n");

	test_job_id_path_traversal();
	test_job_id_special_chars();
	test_job_id_length();
	test_policy_injection_is_escaped();
	test_unterminated_job_id_payload();
	test_oversized_protocol_payload();
	test_hostile_run_request();
	test_dryrun_output_is_bounded();
	test_doctor_output_is_bounded();
	test_env_is_not_inherited();
	test_env_override();

	TEST_SUMMARY();
}
