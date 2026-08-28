#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "jobd.h"
#include "state.h"
#include "testutil.h"

static char g_tmp_state[256];

static void setup_state_dir(void)
{
	snprintf(g_tmp_state, sizeof(g_tmp_state),
	         "/tmp/jobd-state-test-%d", (int)getpid());

	char err[256];
	jobd_config_set("state_dir", g_tmp_state, err, sizeof(err));
	mkdir(g_tmp_state, 0700);
}

static void teardown_state_dir(void)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "%s/jobs", g_tmp_state);
	rmdir(cmd);
	rmdir(g_tmp_state);
}

static void make_job(struct job *job, const char *id)
{
	char err[256];
	job_set_defaults(job);
	snprintf(job->id, sizeof(job->id), "%s", id);
	job_add_arg(job, "/bin/true", err, sizeof(err));
}

static void test_table_add_find(void)
{
	TEST("job table add and find");

	job_table_init();

	struct job job;
	make_job(&job, "table-1");

	struct job_entry *e = job_table_add(&job);
	ASSERT(e != NULL, "add failed");
	ASSERT(job_table_size() == 1, "size should be 1");

	struct job_entry *found = job_table_find("table-1");
	ASSERT(found != NULL, "find failed");
	ASSERT(strcmp(found->job.id, "table-1") == 0, "wrong job returned");
	ASSERT(job_table_find("missing") == NULL,
	       "an unknown ID should not be found");
	PASS();
}

static void test_new_entry_fds_are_invalid(void)
{
	TEST("a new entry starts with invalid descriptors");

	job_table_init();

	struct job job;
	make_job(&job, "fds");
	struct job_entry *e = job_table_add(&job);

	ASSERT(e != NULL, "add failed");
	ASSERT(e->pidfd == -1, "pidfd should start at -1");
	ASSERT(e->timer_fd == -1, "timer_fd should start at -1");
	ASSERT(e->log_wd == -1, "log_wd should start at -1");
	ASSERT(e->waiter_count == 0, "waiter count should start at 0");
	PASS();
}

static void test_table_remove(void)
{
	TEST("job table removal");

	job_table_init();

	struct job a, b;
	make_job(&a, "rm-a");
	make_job(&b, "rm-b");
	job_table_add(&a);
	job_table_add(&b);

	job_table_remove("rm-a");
	ASSERT(job_table_size() == 1, "size should drop to 1");
	ASSERT(job_table_find("rm-a") == NULL, "removed job still found");
	ASSERT(job_table_find("rm-b") != NULL, "other job disappeared");

	job_table_remove("does-not-exist");
	ASSERT(job_table_size() == 1, "removing an unknown ID changed size");
	PASS();
}

static int g_seen;

static void count_each(struct job_entry *e, void *ctx)
{
	(void)e; (void)ctx;
	g_seen++;
}

static void test_table_foreach(void)
{
	TEST("job table iteration");

	job_table_init();

	for (int i = 0; i < 10; i++) {
		struct job job;
		char id[32];
		snprintf(id, sizeof(id), "iter-%d", i);
		make_job(&job, id);
		job_table_add(&job);
	}

	g_seen = 0;
	job_table_foreach(count_each, NULL);
	ASSERT(g_seen == 10, "iteration visited the wrong number of jobs");
	PASS();
}

static void test_state_save_and_load(void)
{
	TEST("state survives save and load");

	setup_state_dir();

	struct job job;
	char err[256];
	make_job(&job, "persist-1");
	job.state       = JOB_EXITED;
	job.exit_code   = 42;
	job.exit_signal = 0;
	job.exit_reason = JOB_EXIT_NORMAL;
	job.pids_max    = 77;

	ASSERT(job_state_save(&job, err, sizeof(err)) == 0, err);

	struct job loaded;
	ASSERT(job_state_load("persist-1", &loaded, err, sizeof(err)) == 0, err);
	ASSERT(strcmp(loaded.id, "persist-1") == 0, "id mismatch");
	ASSERT(loaded.state == JOB_EXITED, "state was not restored");
	ASSERT(loaded.exit_code == 42, "exit code was not restored");
	ASSERT(loaded.pids_max == 77, "pids_max was not restored");
	ASSERT(loaded.exit_reason == JOB_EXIT_NORMAL, "reason was not restored");

	job_state_delete("persist-1");

	struct job gone;
	ASSERT(job_state_load("persist-1", &gone, err, sizeof(err)) != 0,
	       "load should fail after delete");

	teardown_state_dir();
	PASS();
}

static void test_state_escapes_argv(void)
{
	TEST("state file escapes hostile argv");

	setup_state_dir();

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "escape-1");
	job_add_arg(&job, "/bin/echo", err, sizeof(err));
	job_add_arg(&job, "\",\"injected\":\"yes\nnewline", err, sizeof(err));

	ASSERT(job_state_save(&job, err, sizeof(err)) == 0, err);

	struct job loaded;
	ASSERT(job_state_load("escape-1", &loaded, err, sizeof(err)) == 0, err);
	ASSERT(strstr(loaded.argv_buf, "injected") != NULL,
	       "the value should round trip as data");

	char path[512];
	snprintf(path, sizeof(path), "%s/jobs/escape-1/state.json", g_tmp_state);
	FILE *f = fopen(path, "r");
	ASSERT(f != NULL, "state file missing");

	char text[4096];
	size_t n = fread(text, 1, sizeof(text) - 1, f);
	fclose(f);
	text[n] = '\0';

	int lines = 0;
	for (const char *p = text; *p; p++) {
		if (*p == '\n')
			lines++;
	}
	ASSERT(lines == 1, "the record must stay on a single line");

	job_state_delete("escape-1");
	teardown_state_dir();
	PASS();
}

static void test_state_load_rejects_bad_id(void)
{
	TEST("state load rejects an invalid job ID");

	struct job job;
	char err[256];
	ASSERT(job_state_load("../../etc/passwd", &job, err, sizeof(err)) != 0,
	       "traversal in a job ID must be refused");
	PASS();
}

int main(void)
{
	printf("=== state tests ===\n\n");

	test_table_add_find();
	test_new_entry_fds_are_invalid();
	test_table_remove();
	test_table_foreach();
	test_state_save_and_load();
	test_state_escapes_argv();
	test_state_load_rejects_bad_id();

	TEST_SUMMARY();
}
