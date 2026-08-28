#define _GNU_SOURCE
#include <string.h>

#include "jobd.h"
#include "testutil.h"

static void base_job(struct job *job)
{
	char err[256];
	job_set_defaults(job);
	snprintf(job->id, sizeof(job->id), "test-job");
	job_add_arg(job, "/bin/true", err, sizeof(err));
}

static void test_defaults(void)
{
	TEST("defaults are sane");

	struct job job;
	job_set_defaults(&job);

	ASSERT(job.pids_max == 128, "pids_max default");
	ASSERT(job.cpu_max_q == 100000 && job.cpu_max_p == 100000,
	       "cpu_max default");
	ASSERT(job.timeout_ms == 300000, "timeout default");
	ASSERT(job.network_mode == JOBD_NETWORK_NONE, "network default");
	ASSERT(job.fanotify_mode == JOBD_FANOTIFY_OFF, "fanotify default");
	ASSERT(job.argc == 0, "argc default");
	PASS();
}

static void test_valid_job_accepted(void)
{
	TEST("a well-formed job is accepted");

	struct job job;
	char err[256];
	base_job(&job);

	ASSERT(job_validate(&job, err, sizeof(err)) == 0, err);
	PASS();
}

static void test_empty_argv_rejected(void)
{
	TEST("empty argv is rejected");

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "test-job");

	ASSERT(job_validate(&job, err, sizeof(err)) != 0,
	       "a job with no command should be rejected");
	PASS();
}

static void test_relative_command_rejected(void)
{
	TEST("a relative command path is rejected");

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "test-job");
	job_add_arg(&job, "true", err, sizeof(err));

	ASSERT(job_validate(&job, err, sizeof(err)) != 0,
	       "the command must be an absolute path");
	PASS();
}

static void test_zero_pids_rejected(void)
{
	TEST("pids_max of zero is rejected");

	struct job job;
	char err[256];
	base_job(&job);
	job.pids_max = 0;

	ASSERT(job_validate(&job, err, sizeof(err)) != 0,
	       "pids_max must be greater than zero");
	PASS();
}

static void test_bad_network_mode_rejected(void)
{
	TEST("an unsupported network mode is rejected");

	struct job job;
	char err[256];
	base_job(&job);
	job.network_mode = 7;

	ASSERT(job_validate(&job, err, sizeof(err)) != 0,
	       "only network=none is supported");
	PASS();
}

static void test_client_paths_validated(void)
{
	TEST("client paths reject traversal and relative forms");

	const char *bad[] = {
		"relative/path", "../escape", "/ok/../../escape",
		"/trailing/..", "/double//slash", "/control\nchar", NULL
	};

	for (int i = 0; bad[i]; i++) {
		struct job job;
		char err[256];
		base_job(&job);
		snprintf(job.rw_paths[0], JOBD_MAX_PATH_LEN, "%s", bad[i]);
		job.rw_count = 1;

		if (job_validate(&job, err, sizeof(err)) == 0) {
			FAIL(bad[i]);
			return;
		}
	}

	struct job job;
	char err[256];
	base_job(&job);
	snprintf(job.rw_paths[0], JOBD_MAX_PATH_LEN, "/workspace/data");
	job.rw_count = 1;
	ASSERT(job_validate(&job, err, sizeof(err)) == 0,
	       "a normal absolute path should be accepted");
	PASS();
}

static void test_layer_must_not_be_a_path(void)
{
	TEST("a layer name may not be a path");

	struct job job;
	char err[256];
	base_job(&job);
	snprintf(job.layers[0], JOBD_MAX_PATH_LEN, "../../etc");
	job.layer_count = 1;

	ASSERT(job_validate(&job, err, sizeof(err)) != 0,
	       "a layer containing '/' should be rejected");
	PASS();
}

static void test_argv_vector(void)
{
	TEST("argv vector is built correctly");

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "vec");

	ASSERT(job_add_arg(&job, "/bin/sh", err, sizeof(err)) == 0, err);
	ASSERT(job_add_arg(&job, "-c", err, sizeof(err)) == 0, err);
	ASSERT(job_add_arg(&job, "echo hi", err, sizeof(err)) == 0, err);

	char *av[JOBD_MAX_ARGV + 1];
	int n = job_argv(&job, av, JOBD_MAX_ARGV + 1);

	ASSERT(n == 3, "wrong argument count");
	ASSERT(strcmp(av[0], "/bin/sh") == 0, "argv[0]");
	ASSERT(strcmp(av[1], "-c") == 0, "argv[1]");
	ASSERT(strcmp(av[2], "echo hi") == 0, "argv[2] should keep its space");
	ASSERT(av[3] == NULL, "must be NULL terminated");
	PASS();
}

static void test_argv_limit(void)
{
	TEST("argv count limit is enforced");

	struct job job;
	char err[256];
	job_set_defaults(&job);

	int rejected = 0;
	for (int i = 0; i < JOBD_MAX_ARGV + 10; i++) {
		if (job_add_arg(&job, "/x", err, sizeof(err)) != 0) {
			rejected = 1;
			break;
		}
	}

	ASSERT(rejected, "should stop accepting arguments at the limit");
	ASSERT(job.argc <= JOBD_MAX_ARGV, "argc exceeded the limit");
	PASS();
}

static void test_env_entries(void)
{
	TEST("environment entries require KEY=VALUE");

	struct job job;
	char err[256];
	job_set_defaults(&job);

	ASSERT(job_add_env(&job, "KEY=value", err, sizeof(err)) == 0, err);
	ASSERT(job_add_env(&job, "NOEQUALS", err, sizeof(err)) != 0,
	       "an entry without '=' should be rejected");
	ASSERT(job_add_env(&job, "=novalue", err, sizeof(err)) != 0,
	       "an entry with an empty key should be rejected");
	ASSERT(job.envc == 1, "only the valid entry should be stored");
	PASS();
}

static void test_argv_display(void)
{
	TEST("display rendering joins with spaces");

	struct job job;
	char err[256];
	job_set_defaults(&job);
	job_add_arg(&job, "/bin/echo", err, sizeof(err));
	job_add_arg(&job, "a b", err, sizeof(err));

	char out[128];
	job_argv_display(&job, out, sizeof(out));
	ASSERT(strcmp(out, "/bin/echo a b") == 0, "unexpected rendering");
	PASS();
}

static void test_state_names(void)
{
	TEST("state and reason names are defined");

	for (int i = JOB_NEW; i <= JOB_CLEANED; i++) {
		const char *n = job_state_name((enum job_state)i);
		if (!n || strcmp(n, "UNKNOWN") == 0) {
			FAIL("a state is missing a name");
			return;
		}
	}
	for (int i = JOB_EXIT_NORMAL; i <= JOB_EXIT_INTERNAL; i++) {
		const char *n = job_exit_reason_name((enum job_exit_reason)i);
		if (!n || strcmp(n, "UNKNOWN") == 0) {
			FAIL("an exit reason is missing a name");
			return;
		}
	}
	PASS();
}

static void test_terminal_states(void)
{
	TEST("terminal states are classified");

	ASSERT(job_state_is_terminal(JOB_EXITED), "EXITED");
	ASSERT(job_state_is_terminal(JOB_KILLED), "KILLED");
	ASSERT(job_state_is_terminal(JOB_FAILED), "FAILED");
	ASSERT(!job_state_is_terminal(JOB_RUNNING), "RUNNING");
	ASSERT(!job_state_is_terminal(JOB_NEW), "NEW");
	PASS();
}

int main(void)
{
	printf("=== job model tests ===\n\n");

	test_defaults();
	test_valid_job_accepted();
	test_empty_argv_rejected();
	test_relative_command_rejected();
	test_zero_pids_rejected();
	test_bad_network_mode_rejected();
	test_client_paths_validated();
	test_layer_must_not_be_a_path();
	test_argv_vector();
	test_argv_limit();
	test_env_entries();
	test_argv_display();
	test_state_names();
	test_terminal_states();

	TEST_SUMMARY();
}
