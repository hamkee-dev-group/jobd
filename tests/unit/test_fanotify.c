#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "jobd.h"
#include "testutil.h"

enum fake_mode {
	PID_PLAIN, PID_NEWLINE, PID_WHITESPACE, PID_NUL_GARBAGE, PID_NUL,
	PID_GARBAGE, PID_EMPTY, PID_OTHER, PID_ZERO, PID_NEGATIVE, PID_PLUS,
	PID_OVERFLOW, PID_OVERSIZE, PID_READ_ERROR, PID_MISSING, EXIT_EARLY,
	EXIT_WITH_PID, PID_ONLY, READY_OTHER, READY_NO_MARK, READY_FEWER_CANARIES,
	READY_PARTIAL, READY_DELAYED
};

static char g_tmp[] = "/tmp/jobd-fanotify-test-XXXXXX";
static char g_dir[JOBD_PATH_LEN_LONG], g_logs[JOBD_PATH_LEN_LONG];
static char g_pidfile[JOBD_PATH_LEN_LONG], g_log[JOBD_PATH_LEN_LONG];
static char g_mode[JOBD_PATH_LEN_LONG], g_stderr[JOBD_PATH_LEN_LONG];

static int fake_fanotifyd(int argc, char **argv)
{
	const char *pidfile = NULL, *output = NULL;
	unsigned canaries = 0;
	for (int i = 1; i + 1 < argc; i++) {
		if (strcmp(argv[i], "--pid-file") == 0)
			pidfile = argv[++i];
		else if (strcmp(argv[i], "--output") == 0)
			output = argv[++i];
		else if (strcmp(argv[i], "--canary") == 0)
			canaries++;
	}
	if (!pidfile || !output)
		return 2;

	char path[JOBD_PATH_LEN_LONG + 16];
	snprintf(path, sizeof(path), "%s.mode", pidfile);
	FILE *f = fopen(path, "r");
	int mode;
	if (!f)
		return 2;
	int scanned = fscanf(f, "%d", &mode);
	fclose(f);
	if (scanned != 1)
		return 2;

	alarm(10);
	f = fopen(output, "w");
	if (!f)
		return 2;
	fprintf(f, "%ld\n", (long)getpid());
	for (int i = 1; i + 1 < argc; i++) {
		if (strcmp(argv[i], "--canary") == 0)
			fprintf(f, "%s\n", argv[++i]);
	}
	if (fclose(f) != 0)
		return 2;
	if (mode == EXIT_EARLY)
		return 1;

	if (mode == PID_READ_ERROR) {
		if (mkdir(pidfile, 0700) != 0)
			return 2;
	} else if (mode != PID_MISSING) {
		unsigned char bytes[4097];
		size_t len = (size_t)snprintf((char *)bytes, sizeof(bytes),
		                            "%ld", (long)getpid());
		static const unsigned char nul_garbage[] = {
			0, 'g', 'a', 'r', 'b', 'a', 'g', 'e'
		};
		static const unsigned char whitespace[] = {
			' ', '\t', '\r', '\n', '\v', '\f'
		};
		switch (mode) {
		case PID_NEWLINE:
			bytes[len++] = '\n';
			break;
		case PID_WHITESPACE:
			memcpy(bytes + len, whitespace, sizeof(whitespace));
			len += sizeof(whitespace);
			break;
		case PID_NUL_GARBAGE:
			memcpy(bytes + len, nul_garbage, sizeof(nul_garbage));
			len += sizeof(nul_garbage);
			break;
		case PID_NUL:
			bytes[len++] = 0;
			break;
		case PID_GARBAGE:
			bytes[len++] = ' ';
			bytes[len++] = 'x';
			break;
		case PID_EMPTY:
			len = 0;
			break;
		case PID_OTHER:
			len = (size_t)snprintf((char *)bytes, sizeof(bytes),
			                       "%ld", (long)getppid());
			break;
		case PID_ZERO:
			bytes[0] = '0';
			len = 1;
			break;
		case PID_NEGATIVE:
		case PID_PLUS:
			memmove(bytes + 1, bytes, len);
			len++;
			bytes[0] = mode == PID_NEGATIVE ? '-' : '+';
			break;
		case PID_OVERFLOW:
			len = 32;
			memset(bytes, '9', len);
			break;
		case PID_OVERSIZE:
			memset(bytes + len, ' ', sizeof(bytes) - len);
			len = sizeof(bytes);
			break;
		default:
			break;
		}
		/* Publish byte counts, including literal NULs, atomically. */
		snprintf(path, sizeof(path), "%s.tmp", pidfile);
		f = fopen(path, "wb");
		if (!f)
			return 2;
		size_t written = fwrite(bytes, 1, len, f);
		if (fclose(f) != 0 || written != len || rename(path, pidfile) != 0)
			return 2;
	}
	if (mode == READY_DELAYED) {
		struct timespec ts = { .tv_nsec = 250 * 1000000L };
		nanosleep(&ts, NULL);
	}
	if (mode != PID_ONLY) {
		fprintf(stderr, "2026-09-08T00:00:00.000Z INFO  "
		        "fanotifyd started (pid=%ld) -- %u mark(s), "
		        "canaries=%u, burst=0/1000ms%s",
		        (long)(mode == READY_OTHER ? getppid() : getpid()),
		        mode == READY_NO_MARK ? 0u : 1u,
		        mode == READY_FEWER_CANARIES ? canaries - 1 : canaries,
		        mode == READY_PARTIAL ? "" : "\n");
		fflush(stderr);
	}
	if (mode == EXIT_WITH_PID)
		return 1;
	for (;;)
		pause();
}

static void make_job(struct job *job)
{
	job_set_defaults(job);
	snprintf(job->id, sizeof(job->id), "case");
	snprintf(job->root_path, sizeof(job->root_path), "/test root");
	job->fanotify_mode = JOBD_FANOTIFY_DENY;
	job->canary_count = 2;
	snprintf(job->canaries[0], sizeof(job->canaries[0]), "/first");
	snprintf(job->canaries[1], sizeof(job->canaries[1]), "/second file");
}

static pid_t read_child(const struct job *job, int *paths_match)
{
	FILE *f = fopen(g_log, "r");
	if (!f)
		return 0;
	char line[JOBD_PATH_LEN_LONG + JOBD_MAX_PATH_LEN + 2];
	pid_t pid = 0;
	if (fgets(line, sizeof(line), f))
		pid = (pid_t)strtol(line, NULL, 10);
	*paths_match = job->canary_count <= JOBD_MAX_CANARIES;
	for (uint32_t i = 0; *paths_match && i < job->canary_count; i++) {
		char expected[sizeof(line)];
		snprintf(expected, sizeof(expected), "%s%s\n",
		         job->root_path, job->canaries[i]);
		if (!fgets(line, sizeof(line), f) || strcmp(line, expected) != 0)
			*paths_match = 0;
	}
	if (fgetc(f) != EOF)
		*paths_match = 0;
	fclose(f);
	return pid;
}

static void test_start(const char *name, struct job *job, enum fake_mode mode,
                       int expected, int spawned)
{
	TEST(name);
	FILE *f = fopen(g_mode, "w");
	ASSERT(f != NULL, "cannot configure fake child");
	fprintf(f, "%d\n", mode);
	ASSERT(fclose(f) == 0, "cannot save fake mode");

	struct job_sidecars sc = { .fanotifyd_pid = -1 };
	char err[256];
	struct timespec before, after;
	clock_gettime(CLOCK_MONOTONIC, &before);
	alarm(10);
	int rc = job_fanotify_start(job, &sc, err, sizeof(err));
	alarm(0);
	clock_gettime(CLOCK_MONOTONIC, &after);
	double elapsed = after.tv_sec - before.tv_sec +
	                 (after.tv_nsec - before.tv_nsec) / 1e9;
	int paths_match = 0;
	pid_t child = read_child(job, &paths_match);
	int live = child > 0 && kill(child, 0) == 0;
	int gone = child > 0 && !live && errno == ESRCH;
	errno = 0;
	pid_t w = waitpid(child > 0 ? child : -1, NULL, WNOHANG);
	int reaped = w == -1 && errno == ECHILD;

	/* Check startup's cleanup before cleaning up a buggy implementation. */
	if (w == 0 && child > 0) {
		kill(child, SIGKILL);
		while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
			;
	}
	unlink(g_log);
	unlink(g_pidfile);
	rmdir(g_pidfile);
	unlink(g_mode);
	unlink(g_stderr);

	ASSERT(rc == expected, err);
	ASSERT(elapsed < 6.0, "startup exceeded the polling budget");
	ASSERT((child > 0) == spawned, "unexpected spawn or missing witness");
	if (expected == 0 && spawned) {
		ASSERT(sc.fanotifyd_pid == child && live && w == 0,
		       "ready PID must identify the live child");
		ASSERT(paths_match, "canary arguments changed or were omitted");
		if (mode == READY_DELAYED)
			ASSERT(elapsed >= 0.25, "accepted PID before enforcement readiness");
	} else {
		ASSERT(sc.fanotifyd_pid == 0, "startup left a sidecar PID");
		ASSERT(reaped, "startup left an unreaped or running child");
		ASSERT(!spawned || gone, "failed startup left a live child");
	}
	if (mode == PID_MISSING || mode == PID_ONLY)
		ASSERT(elapsed >= 2.5, "missing readiness did not exhaust polling");
	PASS();
}

static void test_build_argv(void)
{
	TEST("pure argv builder preserves deny and observe arguments");
	struct job job;
	make_job(&job);
	const struct job_sidecars sc = {
		.fanotify_pidfile = "/test.pid", .fanotify_log = "/test.jsonl"
	};
	char *argv[15], canaries[JOBD_MAX_CANARIES][JOBD_PATH_LEN_LONG];
	char err[256];
	const char *expected[] = {
		"/fake", "-f", "--pid-file", "/test.pid", "--output", "/test.jsonl",
		"--perm", "--deny-on-alert", "--filesystem", "/test root",
		"--canary", "/test root/first", "--canary", "/test root/second file"
	};
	ASSERT(job_fanotify_build_argv(&job, "/fake", &sc, argv, 15, canaries,
	                               err, sizeof(err)) == 14, err);
	for (int i = 0; i < 14; i++)
		ASSERT(strcmp(argv[i], expected[i]) == 0, "deny argv mismatch");
	ASSERT(argv[14] == NULL, "argv must be terminated");
	ASSERT(argv[11] == canaries[0] && argv[13] == canaries[1],
	       "canary strings must use caller storage");
	job.fanotify_mode = JOBD_FANOTIFY_OBSERVE;
	ASSERT(job_fanotify_build_argv(&job, "/fake", &sc, argv, 14, canaries,
	                               err, sizeof(err)) == 13, err);
	for (int i = 0; i < 13; i++)
		ASSERT(strcmp(argv[i], expected[i < 7 ? i : i + 1]) == 0,
		       "observe argv must keep permission events and omit deny");
	ASSERT(argv[13] == NULL, "observe argv must be terminated");
	PASS();
}

static void test_build_limits(void)
{
	TEST("argv builder rejects insufficient storage and canary overflow");
	struct job job;
	make_job(&job);
	const struct job_sidecars sc = {0};
	char *argv[15], canaries[JOBD_MAX_CANARIES][JOBD_PATH_LEN_LONG];
	char err[256], sentinel;
	argv[14] = &sentinel;
	ASSERT(job_fanotify_build_argv(&job, "/fake", &sc, argv, 14, canaries,
	                               err, sizeof(err)) == -1, "small argv accepted");
	ASSERT(argv[0] == NULL && argv[14] == &sentinel,
	       "failure must not publish argv or write past capacity");
	ASSERT(job_fanotify_build_argv(&job, "/fake", &sc, NULL, 0, canaries,
	                               err, sizeof(err)) == -1, "zero capacity accepted");
	job.canary_count = UINT32_MAX;
	ASSERT(job_fanotify_build_argv(&job, "/fake", &sc, argv, 15, canaries,
	                               err, sizeof(err)) == -1, "count overflow accepted");
	make_job(&job);
	memset(job.root_path, 'r', sizeof(job.root_path) - 1);
	job.root_path[sizeof(job.root_path) - 1] = '\0';
	ASSERT(job_fanotify_build_argv(&job, "/fake", &sc, argv, 15, canaries,
	                               err, sizeof(err)) == -1, "path overflow accepted");
	ASSERT(argv[0] == NULL, "failed construction published partial argv");
	PASS();
}

static int setup(void)
{
	char err[256];
	if (!mkdtemp(g_tmp) ||
	    jobd_config_set("runtime_dir", g_tmp, err, sizeof(err)) != 0 ||
	    jobd_config_set("fanotifyd", "/proc/self/exe", err, sizeof(err)) != 0)
		return -1;
	if (jobd_job_dir("case", g_dir, sizeof(g_dir)) != 0 ||
	    jobd_job_subdir("case", "logs", g_logs, sizeof(g_logs)) != 0 ||
	    jobd_job_subdir("case", "logs/fanotifyd.jsonl", g_log, sizeof(g_log)) != 0 ||
	    jobd_job_subdir("case", "logs/fanotifyd.stderr", g_stderr, sizeof(g_stderr)) != 0 ||
	    jobd_job_subdir("case", "fanotifyd.pid", g_pidfile, sizeof(g_pidfile)) != 0 ||
	    jobd_job_subdir("case", "fanotifyd.pid.mode", g_mode, sizeof(g_mode)) != 0)
		return -1;
	return mkdir(g_dir, 0700) == 0 && mkdir(g_logs, 0700) == 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "-f") == 0)
		return fake_fanotifyd(argc, argv);
	setvbuf(stdout, NULL, _IONBF, 0);
	printf("=== fanotify tests ===\n\n");
	test_build_argv();
	test_build_limits();
	if (setup() != 0) {
		perror("fanotify test setup");
		return 1;
	}
	struct job job;
	make_job(&job);
	static const struct {
		const char *name;
		enum fake_mode mode;
		int expected;
	} cases[] = {
		{ "live child PID followed by literal NUL and garbage is rejected", PID_NUL_GARBAGE, -1 },
		{ "PID without newline is ready", PID_PLAIN, 0 },
		{ "PID with newline is ready", PID_NEWLINE, 0 },
		{ "PID with ASCII whitespace is ready", PID_WHITESPACE, 0 },
		{ "trailing NUL is rejected", PID_NUL, -1 },
		{ "trailing text is rejected", PID_GARBAGE, -1 },
		{ "empty pidfile is rejected", PID_EMPTY, -1 },
		{ "another live process PID is rejected", PID_OTHER, -1 },
		{ "zero PID is rejected", PID_ZERO, -1 },
		{ "negative PID is rejected", PID_NEGATIVE, -1 },
		{ "plus-prefixed PID is rejected", PID_PLUS, -1 },
		{ "numeric overflow is rejected", PID_OVERFLOW, -1 },
		{ "oversized valid prefix and whitespace are rejected", PID_OVERSIZE, -1 },
		{ "pidfile read error is rejected", PID_READ_ERROR, -1 },
		{ "missing pidfile times out and reaps the child", PID_MISSING, -1 },
		{ "early child exit fails startup", EXIT_EARLY, -1 },
		{ "exited child with readiness is not ready", EXIT_WITH_PID, -1 },
		{ "live child with only a pidfile is not ready", PID_ONLY, -1 },
		{ "another PID in the startup message is rejected", READY_OTHER, -1 },
		{ "startup without a filesystem mark is rejected", READY_NO_MARK, -1 },
		{ "startup with fewer canaries is rejected", READY_FEWER_CANARIES, -1 },
		{ "incomplete startup message is rejected", READY_PARTIAL, -1 },
		{ "startup waits for enforcement readiness after the pidfile", READY_DELAYED, 0 },
	};
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++)
		test_start(cases[i].name, &job, cases[i].mode, cases[i].expected, 1);

	job.fanotify_mode = JOBD_FANOTIFY_OBSERVE;
	job.canary_count = JOBD_MAX_CANARIES;
	for (uint32_t i = 0; i < job.canary_count; i++)
		snprintf(job.canaries[i], sizeof(job.canaries[i]), "/canary %u", i);
	test_start("maximum canary count passes every path unchanged", &job,
	           PID_NEWLINE, 0, 1);
	job.canary_count++;
	test_start("excess canary count is rejected before spawning", &job,
	           PID_NEWLINE, -1, 0);
	make_job(&job);
	memset(job.root_path, 'r', sizeof(job.root_path) - 2);
	job.root_path[0] = '/';
	job.root_path[sizeof(job.root_path) - 2] = '\0';
	snprintf(job.canaries[0], sizeof(job.canaries[0]), "/");
	snprintf(job.canaries[1], sizeof(job.canaries[1]), "/");
	test_start("canary paths with exactly enough space are unchanged", &job,
	           PID_NEWLINE, 0, 1);
	snprintf(job.canaries[1], sizeof(job.canaries[1]), "/x");
	test_start("one overflowing canary rejects the entire startup", &job,
	           PID_NEWLINE, -1, 0);
	job.canary_count = JOBD_MAX_CANARIES + 1;
	job.fanotify_mode = JOBD_FANOTIFY_OFF;
	test_start("fanotify off skips spawning and canary validation", &job,
	           PID_NEWLINE, 0, 0);
	rmdir(g_logs);
	rmdir(g_dir);
	rmdir(g_tmp);
	TEST_SUMMARY();
}
