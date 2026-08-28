#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>

#include "jobd.h"
#include "testutil.h"

static void make_job(struct job *job, const char *id)
{
	char err[256];
	job_set_defaults(job);
	snprintf(job->id, sizeof(job->id), "%s", id);
	job_add_arg(job, "/usr/bin/python3", err, sizeof(err));
	job_add_arg(job, "/workspace/job.py", err, sizeof(err));
}

static void test_plan_has_sections(void)
{
	TEST("the plan contains every section");

	struct job job;
	make_job(&job, "plan-1");

	char plan[65536];
	ASSERT(jobd_policy_plan_dryrun(&job, plan, sizeof(plan)) == 0,
	       "dry run failed");

	static const char *sections[] = {
		"[job]", "[components]", "[overlay]", "[landlock_paths]",
		"[seccomp_deny]", "[cgroup_limits]", "[network]", "[fanotify]",
		"[memfdbus]", "[iouringd]", "[argv_chain]", "[environment]",
		"[cleanup_plan]", "[security_downgrade_rules]", NULL
	};

	for (int i = 0; sections[i]; i++) {
		if (!strstr(plan, sections[i])) {
			FAIL(sections[i]);
			return;
		}
	}
	PASS();
}

static void test_plan_rejects_invalid_job(void)
{
	TEST("the plan reports validation failure");

	struct job job;
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "bad id with spaces");

	char plan[4096];
	ASSERT(jobd_policy_plan_dryrun(&job, plan, sizeof(plan)) == 0,
	       "dry run should still return 0");
	ASSERT(strstr(plan, "VALIDATION FAILED") != NULL,
	       "should report the validation failure");
	PASS();
}

static void test_plan_includes_seccomp_denies(void)
{
	TEST("the plan lists every denied syscall");

	struct job job;
	make_job(&job, "plan-seccomp");

	char plan[65536];
	jobd_policy_plan_dryrun(&job, plan, sizeof(plan));

	const char *const *deny = job_seccomp_deny_list();
	for (int i = 0; deny[i]; i++) {
		char needle[64];
		snprintf(needle, sizeof(needle), "deny_syscall             = %s\n",
		         deny[i]);
		if (!strstr(plan, needle)) {
			FAIL(deny[i]);
			return;
		}
	}

	static const char *expected[] = {
		"ptrace", "bpf", "perf_event_open", "init_module",
		"mount", "pivot_root", "unshare", "setns", NULL
	};
	for (int i = 0; expected[i]; i++) {
		if (!strstr(plan, expected[i])) {
			FAIL(expected[i]);
			return;
		}
	}
	PASS();
}

static void test_deny_list_uses_known_names(void)
{
	TEST("the deny list avoids names landlockd rejects");

	static const char *unknown[] = {
		"kexec_file_load", "keyctl", "add_key", "request_key",
		"name_to_handle_at", NULL
	};

	const char *const *deny = job_seccomp_deny_list();
	for (int i = 0; deny[i]; i++) {
		for (int j = 0; unknown[j]; j++) {
			if (strcmp(deny[i], unknown[j]) == 0) {
				FAIL(deny[i]);
				return;
			}
		}
	}

	static const char *must_not_deny[] = { "socket", "clone3", NULL };
	for (int i = 0; deny[i]; i++) {
		for (int j = 0; must_not_deny[j]; j++) {
			if (strcmp(deny[i], must_not_deny[j]) == 0) {
				FAIL(deny[i]);
				return;
			}
		}
	}
	PASS();
}

static void test_plan_paths_match_configuration(void)
{
	TEST("plan paths follow the configured runtime directory");

	char err[256];
	ASSERT(jobd_config_set("runtime_dir", "/tmp/jobd-plan-test",
	                         err, sizeof(err)) == 0, err);

	struct job job;
	make_job(&job, "plan-paths");

	char plan[65536];
	jobd_policy_plan_dryrun(&job, plan, sizeof(plan));

	ASSERT(strstr(plan, "/tmp/jobd-plan-test/plan-paths/root") != NULL,
	       "the plan should use the configured runtime directory");
	ASSERT(strstr(plan, "/tmp/jobd-plan-test/plan-paths/logs") != NULL,
	       "the plan should name the real log directory");

	jobd_config_set("runtime_dir", "/run/jobd", err, sizeof(err));
	PASS();
}

static void test_plan_reflects_options(void)
{
	TEST("the plan reflects the requested options");

	struct job job;
	make_job(&job, "plan-opts");
	job.iouring_enabled = 1;
	job.fanotify_mode   = JOBD_FANOTIFY_DENY;
	job.memfd_input_count = 1;
	snprintf(job.memfd_inputs[0].name, JOBD_MAX_PATH_LEN, "model");
	snprintf(job.memfd_inputs[0].path, JOBD_MAX_PATH_LEN, "/srv/model.bin");

	char plan[65536];
	jobd_policy_plan_dryrun(&job, plan, sizeof(plan));

	ASSERT(strstr(plan, "model <- /srv/model.bin") != NULL,
	       "the memfd input should be listed");
	ASSERT(strstr(plan, "freeze then kill") != NULL,
	       "deny mode should describe the reaction");
	ASSERT(strstr(plan, "IOURINGD_SOCKET") != NULL,
	       "the iouring socket should appear in the environment");
	PASS();
}

static void test_plan_lists_each_argument(void)
{
	TEST("each argument is listed separately");

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "plan-argv");
	job_add_arg(&job, "/bin/echo", err, sizeof(err));
	job_add_arg(&job, "one two", err, sizeof(err));

	char plan[65536];
	jobd_policy_plan_dryrun(&job, plan, sizeof(plan));

	ASSERT(strstr(plan, "5_argv[0]") != NULL, "argv[0] should be listed");
	ASSERT(strstr(plan, "5_argv[1]") != NULL, "argv[1] should be listed");
	ASSERT(strstr(plan, "one two") != NULL,
	       "an argument with a space should stay whole");
	PASS();
}

static void test_plan_environment_is_minimal(void)
{
	TEST("the planned environment is the documented minimum");

	struct job job;
	make_job(&job, "plan-env");

	char plan[65536];
	jobd_policy_plan_dryrun(&job, plan, sizeof(plan));

	ASSERT(strstr(plan, "PATH=/usr/bin:/bin") != NULL, "PATH");
	ASSERT(strstr(plan, "HOME=/workspace") != NULL, "HOME");
	ASSERT(strstr(plan, "TMPDIR=/tmp") != NULL, "TMPDIR");
	ASSERT(strstr(plan, "LANG=C.UTF-8") != NULL, "LANG");
	ASSERT(strstr(plan, "JOBD_JOB_ID=plan-env") != NULL, "JOBD_JOB_ID");
	PASS();
}

int main(void)
{
	printf("=== policy / dry-run tests ===\n\n");

	test_plan_has_sections();
	test_plan_rejects_invalid_job();
	test_plan_includes_seccomp_denies();
	test_deny_list_uses_known_names();
	test_plan_paths_match_configuration();
	test_plan_reflects_options();
	test_plan_lists_each_argument();
	test_plan_environment_is_minimal();

	TEST_SUMMARY();
}
