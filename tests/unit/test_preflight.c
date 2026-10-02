#define _GNU_SOURCE
#include <string.h>
#include <sys/inotify.h>

#include "jobd.h"
#include "state.h"
#include "testutil.h"

static void make_job(struct job *job, uint8_t fanotify_mode)
{
	char err[256];
	job_set_defaults(job);
	snprintf(job->id, sizeof(job->id), "preflight-job");
	job_add_arg(job, "/bin/true", err, sizeof(err));
	job->fanotify_mode = fanotify_mode;
}

static int refused_for_inotify(const struct job *job)
{
	char err[256];
	return job_preflight(job, err, sizeof(err)) != 0 &&
	       strstr(err, "monitored job") != NULL;
}

static void test_missing_backend_rejects_monitored(void)
{
	TEST("an unavailable or unregistered inotify backend rejects "
	     "observe and deny");

	struct job job;
	job_inotify_set_ready(0);

	make_job(&job, JOBD_FANOTIFY_OBSERVE);
	ASSERT(refused_for_inotify(&job), "observe should be refused");
	make_job(&job, JOBD_FANOTIFY_DENY);
	ASSERT(refused_for_inotify(&job), "deny should be refused");
	PASS();
}

static void test_fanotify_off_not_gated(void)
{
	TEST("fanotify-off jobs are not gated on inotify");

	struct job job;
	job_inotify_set_ready(0);
	make_job(&job, JOBD_FANOTIFY_OFF);
	ASSERT(!refused_for_inotify(&job), "off must not be refused");
	PASS();
}

static void test_ready_backend_not_gated(void)
{
	TEST("a registered inotify backend lets monitored jobs through");

	struct job job;
	job_inotify_set_ready(1);
	make_job(&job, JOBD_FANOTIFY_OBSERVE);
	ASSERT(!refused_for_inotify(&job), "observe must pass the gate");
	make_job(&job, JOBD_FANOTIFY_DENY);
	ASSERT(!refused_for_inotify(&job), "deny must pass the gate");
	PASS();
}

static void test_launch_stops_at_preflight(uint8_t mode, int inotify_fd)
{
	TEST("missing or unregistered backend stops monitored launch at preflight");

	static struct job_entry e;
	memset(&e, 0, sizeof(e));
	e.pidfd = e.timer_fd = e.log_wd = -1;
	char resp[2048];
	struct agd_buf out;

	job_inotify_set_ready(0);
	make_job(&e.job, mode);
	agd_buf_init(&out, resp, sizeof(resp));

	ASSERT(job_launch(&e, inotify_fd, &out) != 0, "launch should fail");
	ASSERT(e.job.state == JOB_FAILED &&
	       e.job.exit_reason == JOB_EXIT_SETUP, "job should fail in setup");
	ASSERT(strstr(resp, "FAIL preflight") != NULL, resp);
	ASSERT(strstr(resp, "step1") == NULL && e.workload_pid == 0,
	       "nothing may be launched");
	ASSERT(e.log_wd == -1 && !e.log_identity_set,
	       "rejected launch must not initialize per-job monitoring");
	PASS();
}

int main(void)
{
	printf("=== preflight tests ===\n\n");

	test_missing_backend_rejects_monitored();
	test_fanotify_off_not_gated();
	test_ready_backend_not_gated();
	int fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (fd < 0)
		return 1;
	for (uint8_t mode = JOBD_FANOTIFY_OBSERVE; mode <= JOBD_FANOTIFY_DENY; mode++) {
		test_launch_stops_at_preflight(mode, -1);
		test_launch_stops_at_preflight(mode, fd);
	}
	close(fd);

	TEST_SUMMARY();
}
