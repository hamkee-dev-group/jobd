#define _GNU_SOURCE
#define main jobd_main
#include "../../src/jobd.c"
#undef main

#include "testutil.h"

static char tmp[] = "/tmp/jobd-monitor-test-XXXXXX";
static char log_path[512], log_dir[512], moved_path[512], replacement[512];
static char result_path[512];
static int writer = -1, release_fd = -1;
static pid_t child;
static int kill_calls, freeze_calls;
static int kill_fails, freeze_fails, launch_status, alert_count;
static char messages[8192], failure_job[JOBD_MAX_JOB_ID + 1], failure_cause[256];

enum fault_op { NO_FAULT, LOG_OPEN, LOG_STAT, LOG_SEEK, LOG_READ, WATCH, EVENTS };
static enum fault_op fault_op;
static int fault_errno, fault_count, fault_skip, log_read_fd = -1;
static int change_device, inject_event;
static struct inotify_event injected_event;

static void inject(enum fault_op op, int error, int count)
{
	fault_op = op;
	fault_errno = error;
	fault_count = count;
}

static int fault(enum fault_op op)
{
	if (fault_op != op || fault_count == 0)
		return 0;
	if (fault_skip > 0) {
		fault_skip--;
		return 0;
	}
	if (fault_count > 0)
		fault_count--;
	errno = fault_errno;
	return 1;
}

int __real_open(const char *path, int flags, ...);
int __real_close(int fd);
int __real_fstat(int fd, struct stat *st);
off_t __real_lseek(int fd, off_t off, int whence);
ssize_t __real_read(int fd, void *buf, size_t size);
int __real_inotify_add_watch(int fd, const char *path, uint32_t mask);

int __wrap_open(const char *path, int flags, ...)
{
	mode_t mode = 0;
	if (flags & O_CREAT) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
	}
	int log = strcmp(path, log_path) == 0 && (flags & O_ACCMODE) == O_RDONLY;
	if (log && fault(LOG_OPEN))
		return -1;
	int fd = __real_open(path, flags, mode);
	if (log)
		log_read_fd = fd;
	return fd;
}

int __wrap_close(int fd)
{
	if (fd == log_read_fd)
		log_read_fd = -1;
	return __real_close(fd);
}

int __wrap_fstat(int fd, struct stat *st)
{
	if (fd == log_read_fd && fault(LOG_STAT))
		return -1;
	int rc = __real_fstat(fd, st);
	if (rc == 0 && fd == log_read_fd && change_device)
		st->st_dev++;
	return rc;
}

off_t __wrap_lseek(int fd, off_t off, int whence)
{
	if (fd == log_read_fd && fault(LOG_SEEK))
		return -1;
	return __real_lseek(fd, off, whence);
}

ssize_t __wrap_read(int fd, void *buf, size_t size)
{
	if (fd == log_read_fd && fault(LOG_READ))
		return -1;
	if (fd == g_inotify_fd) {
		if (fault(EVENTS))
			return fault_errno ? -1 : 0;
		if (inject_event && size >= sizeof(injected_event)) {
			inject_event = 0;
			memcpy(buf, &injected_event, sizeof(injected_event));
			return sizeof(injected_event);
		}
	}
	return __real_read(fd, buf, size);
}

int __wrap_inotify_add_watch(int fd, const char *path, uint32_t mask)
{
	if (fault(WATCH))
		return -1;
	return __real_inotify_add_watch(fd, path, mask);
}

void __wrap_jobd_log(const char *fmt, ...)
{
	size_t len = strlen(messages);
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(messages + len, sizeof(messages) - len, fmt, ap);
	va_end(ap);
}

void __wrap_jobd_log_event(const char *id, const char *component,
                           const char *event, const char *extra)
{
	(void)component;
	if (strcmp(event, "alert") == 0)
		alert_count++;
	if (strcmp(event, "monitor_failed") == 0) {
		snprintf(failure_job, sizeof(failure_job), "%s", id);
		snprintf(failure_cause, sizeof(failure_cause), "%s", extra);
	}
}

int __wrap_job_cgroup_freeze(const char *id, char *err, size_t sz)
{
	(void)id;
	freeze_calls++;
	snprintf(err, sz, "%s", freeze_fails ? "injected freeze failure" : "freeze ok");
	return freeze_fails ? -1 : 0;
}

int __wrap_job_cgroup_kill(const char *id, char *err, size_t sz)
{
	(void)id;
	kill_calls++;
	snprintf(err, sz, "%s", kill_fails ? "injected kill failure" : "kill ok");
	return kill_fails ? -1 : 0;
}

int __wrap_job_cgroup_remove(const char *id, char *err, size_t sz)
{
	(void)id;
	snprintf(err, sz, "remove ok");
	return 0;
}

int __wrap_job_launch(struct job_entry *e, struct agd_buf *out)
{
	int p[2];
	if (pipe(p) != 0)
		return -1;
	child = fork();
	if (child == 0) {
		close(p[1]);
		alarm(30);
		char c;
		while (read(p[0], &c, 1) < 0 && errno == EINTR)
			;
		_exit(0);
	}
	close(p[0]);
	release_fd = p[1];
	if (child < 0)
		return -1;
	e->child_pid = child;
	e->job.state = JOB_RUNNING;
	snprintf(e->job.log_dir, sizeof(e->job.log_dir), "%s", log_dir);
	snprintf(e->sc.fanotify_log, sizeof(e->sc.fanotify_log), "%s", log_path);
	agd_buf_adds(out, "launched\n");
	return 0;
}

static int setup(void)
{
	kill_calls = freeze_calls = 0;
	kill_fails = freeze_fails = alert_count = 0;
	fault_op = NO_FAULT;
	fault_skip = fault_count = change_device = inject_event = 0;
	messages[0] = failure_job[0] = failure_cause[0] = '\0';
	job_inotify_set_ready(1);
	writer = open(log_path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0600);
	g_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	g_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	return writer >= 0 && g_inotify_fd >= 0 && g_epoll_fd >= 0 ? 0 : -1;
}

static void teardown(void)
{
	if (release_fd >= 0)
		close(release_fd);
	if (child > 0)
		while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
			;
	child = 0;
	release_fd = -1;
	close(writer);
	close(g_inotify_fd);
	close(g_epoll_fd);
	g_inotify_fd = g_epoll_fd = -1;
	job_table_init();
	job_state_delete("monitored");
	unlink(log_path);
	rmdir(log_path);
	unlink(moved_path);
	unlink(replacement);
	unlink(result_path);
}

static struct job_entry *launch(uint8_t mode)
{
	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "monitored");
	job.fanotify_mode = mode;
	if (job_add_arg(&job, "/bin/true", err, sizeof(err)) != 0)
		return NULL;
	uint8_t request[JOBD_MAX_PAYLOAD];
	size_t len;
	if (jobd_encode_run_request(&job, request, sizeof(request), &len,
	                           err, sizeof(err)) != 0)
		return NULL;
	int sockets[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
		return NULL;
	struct jobd_msg_header hdr = { .request_id = 1 };
	char response[RESP_BUF_BYTES];
	handle_run(sockets[0], &hdr, request, len, response);
	uint8_t payload[RESP_BUF_BYTES];
	struct jobd_response resp;
	const uint8_t *data;
	int ok = jobd_recv_msg(sockets[1], &hdr, payload, sizeof(payload), &len) == 0 &&
	         jobd_parse_response(payload, len, &resp, &data) == 0;
	launch_status = ok ? resp.status : -1;
	close(sockets[0]);
	close(sockets[1]);
	return ok && resp.status == JOBD_STATUS_OK ? job_table_find(job.id) : NULL;
}

static int replace_log(void)
{
	int fd = open(replacement, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	close(fd);
	if (rename(log_path, moved_path) != 0 || rename(replacement, log_path) != 0)
		return -1;
	const char alert[] = "{\"alert\":true}\n";
	return write(writer, alert, sizeof(alert) - 1) == sizeof(alert) - 1 ? 0 : -1;
}

static int append_text(const char *text)
{
	size_t len = strlen(text);
	return write(writer, text, len) == (ssize_t)len ? 0 : -1;
}

static int monitoring_failed(const struct job_entry *e, const char *cause)
{
	return e->job.state == JOB_RUNNING && e->monitor_failed &&
	       e->job.exit_reason == JOB_EXIT_INTERNAL && kill_calls > 0 &&
	       strcmp(failure_job, e->job.id) == 0 &&
	       strstr(failure_cause, cause) != NULL &&
	       strstr(messages, "job monitored: monitoring failed:") != NULL;
}

static void test_replacement_event(void)
{
	TEST("real move/replacement events contain a running deny job");
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(JOBD_FANOTIFY_DENY);
	ASSERT(e && e->log_wd >= 0, "production launch did not register a watch");
	handle_inotify();
	ASSERT(kill_calls == 0, "healthy log caused containment");
	ASSERT(replace_log() == 0, "cannot replace log");
	handle_inotify();
	ASSERT(kill_calls > 0 && e->job.exit_reason == JOB_EXIT_INTERNAL,
	       "replacement went unnoticed by the production event handler");
	ASSERT(e->job.state == JOB_RUNNING && waitpid(child, NULL, WNOHANG) == 0,
	       "containment must be requested before job exit");
	PASS();
}

static void test_replacement_sweep(void)
{
	TEST("periodic sweep detects replacement without event delivery");
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(JOBD_FANOTIFY_DENY);
	ASSERT(e && e->log_wd >= 0, "production launch did not register a watch");
	handle_inotify();
	ASSERT(replace_log() == 0, "cannot replace log");
	job_table_foreach(sweep_running, NULL);
	ASSERT(kill_calls > 0 && e->job.exit_reason == JOB_EXIT_INTERNAL,
	       "replacement went unnoticed by the production sweep");
	ASSERT(e->job.state == JOB_RUNNING && waitpid(child, NULL, WNOHANG) == 0,
	       "containment must be requested before job exit");
	PASS();
}

static void test_sweep_without_watch(void)
{
	TEST("periodic monitoring does not depend on a watch descriptor");
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(JOBD_FANOTIFY_DENY);
	ASSERT(e, "launch failed");
	e->log_wd = -1;
	ASSERT(replace_log() == 0, "cannot replace log");
	job_table_foreach(sweep_running, NULL);
	ASSERT(monitoring_failed(e, "device/inode"), "unwatched job escaped scan");
	PASS();
}

enum loss_kind { MISSING, DIRECTORY, TRUNCATED, DEVICE, UNREADABLE, WATCH_LOST,
                 DIRECTORY_MOVED, UNMOUNTED };

static void test_log_loss(enum loss_kind kind, uint8_t mode, const char *cause)
{
	TEST(cause);
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(mode);
	ASSERT(e, "launch failed");
	ASSERT(append_text("{\"info\":true}\n") == 0, "write failed");
	handle_inotify();
	ASSERT(e->log_off > 0 && kill_calls == 0, "initial log was not consumed");
	char moved_dir[512];
	snprintf(moved_dir, sizeof(moved_dir), "%s/moved-logs", tmp);
	switch (kind) {
	case MISSING:
		ASSERT(unlink(log_path) == 0, "unlink failed");
		break;
	case DIRECTORY:
		ASSERT(unlink(log_path) == 0 && mkdir(log_path, 0700) == 0,
		       "directory replacement failed");
		break;
	case TRUNCATED:
		ASSERT(ftruncate(writer, 0) == 0, "truncate failed");
		break;
	case DEVICE:
		change_device = 1;
		job_table_foreach(sweep_running, NULL);
		break;
	case UNREADABLE:
		ASSERT(chmod(log_path, 0000) == 0, "chmod failed");
		/* EACCES is deterministic even when the suite runs as root. */
		inject(LOG_OPEN, EACCES, -1);
		break;
	case WATCH_LOST:
		ASSERT(inotify_rm_watch(g_inotify_fd, e->log_wd) == 0, "rm_watch failed");
		break;
	case DIRECTORY_MOVED:
		ASSERT(rename(log_dir, moved_dir) == 0, "directory move failed");
		handle_inotify();
		ASSERT(rename(moved_dir, log_dir) == 0, "directory restore failed");
		break;
	case UNMOUNTED:
		injected_event = (struct inotify_event){ .wd = e->log_wd, .mask = IN_UNMOUNT };
		inject_event = 1;
		break;
	}
	handle_inotify();
	ASSERT(monitoring_failed(e, cause), "log/watch loss was not recorded and contained");
	if (kind == WATCH_LOST)
		ASSERT(e->log_wd == -1, "stale watch descriptor retained");
	PASS();
}

static void test_io_failure(enum fault_op op, int error, int after_data,
                            const char *cause)
{
	TEST(cause);
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(JOBD_FANOTIFY_DENY);
	ASSERT(e, "launch failed");
	ASSERT(append_text("{\"info\":true}\n") == 0, "write failed");
	inject(op, error, -1);
	fault_skip = after_data;
	job_table_foreach(sweep_running, NULL);
	ASSERT(monitoring_failed(e, cause), "permanent I/O error treated as EOF");
	if (after_data)
		ASSERT(e->log_off > 0, "read failure was not injected after data");
	PASS();
}

static void test_eintr(enum fault_op op)
{
	TEST("interrupted monitoring operation is retried");
	ASSERT(setup() == 0, "setup failed");
	inject(op, EINTR, 1);
	struct job_entry *e = launch(JOBD_FANOTIFY_OBSERVE);
	ASSERT(e, "EINTR rejected launch");
	ASSERT(append_text("{\"alert\":true}\n") == 0, "write failed");
	handle_inotify();
	ASSERT(fault_count == 0, "fault was not exercised");
	ASSERT(!e->monitor_failed && kill_calls == 0 && alert_count == 1,
	       "interruption caused failure or lost the alert");
	job_table_foreach(sweep_running, NULL);
	ASSERT(kill_calls == 0 && alert_count == 1, "clean EOF was not harmless");
	PASS();
}

static void test_modes(uint8_t mode)
{
	TEST("valid alerts retain deny, observe, and off semantics");
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(mode);
	ASSERT(e, "launch failed");
	ASSERT(append_text("{\"alert\":true}\n") == 0, "write failed");
	handle_inotify();
	job_table_foreach(sweep_running, NULL);
	ASSERT(alert_count == (mode != JOBD_FANOTIFY_OFF), "wrong alert logging");
	ASSERT(kill_calls == (mode == JOBD_FANOTIFY_DENY), "wrong enforcement mode");
	ASSERT(e->job.exit_reason == (mode == JOBD_FANOTIFY_DENY ?
	       JOB_EXIT_POLICY : JOB_EXIT_NORMAL), "wrong alert exit reason");
	if (mode == JOBD_FANOTIFY_OFF) {
		ASSERT(e->log_wd == -1 && !e->log_identity_set, "off established monitoring");
		ASSERT(unlink(log_path) == 0, "unlink failed");
		job_table_foreach(sweep_running, NULL);
		ASSERT(kill_calls == 0 && !e->monitor_failed, "off enforced monitoring loss");
	}
	PASS();
}

static void test_reaction_failure(int fail_kill, int events)
{
	TEST("failed freeze still kills; failed kill propagates and retries without new data");
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(JOBD_FANOTIFY_DENY);
	ASSERT(e, "launch failed");
	freeze_fails = 1;
	kill_fails = fail_kill;
	ASSERT(append_text("{\"denied\":true}\n") == 0, "write failed");
	int rc = 0;
	if (events)
		handle_inotify();
	else
		rc = job_monitor_scan_alerts(e);
	ASSERT(freeze_calls == 1 && kill_calls == 1, "freeze failure prevented kill");
	ASSERT(strstr(messages, "injected freeze failure"), "freeze failure not logged");
	ASSERT(e->job.exit_reason == JOB_EXIT_POLICY, "deny lost policy reason");
	if (!events)
		ASSERT(rc == (fail_kill ? -1 : 1), "reaction error did not propagate");
	ASSERT(e->reacted == !fail_kill && e->containment_pending == fail_kill,
	       "failed containment was marked complete");
	long off = e->log_off;
	ASSERT(off > 0, "alert was not consumed");
	kill_fails = 0;
	job_table_foreach(sweep_running, NULL);
	ASSERT(kill_calls == (fail_kill ? 2 : 1) && e->reacted &&
	       !e->containment_pending, "sweep did not complete pending containment");
	ASSERT(e->log_off == off && alert_count == 1, "retry required rereading the alert");
	PASS();
}

static void test_launch_failure(enum fault_op op)
{
	TEST("monitor setup failure rejects launch and keeps pending containment supervised");
	ASSERT(setup() == 0, "setup failed");
	if (op == NO_FAULT)
		ASSERT(unlink(log_path) == 0, "unlink failed");
	else
		inject(op, op == WATCH ? ENOSPC : EACCES, -1);
	kill_fails = 1;
	ASSERT(launch(JOBD_FANOTIFY_DENY) == NULL &&
	       launch_status == JOBD_STATUS_ERR_INTERNAL, "unmonitored launch succeeded");
	struct job_entry *e = job_table_find("monitored");
	ASSERT(e && monitoring_failed(e, op == WATCH ? "watch" : "open"),
	       "launched workload was not contained after monitor setup failed");
	ASSERT(!e->reacted && e->containment_pending && waitpid(child, NULL, WNOHANG) == 0,
	       "pending launch was removed from supervision");
	int calls = kill_calls;
	kill_fails = 0;
	job_table_foreach(sweep_running, NULL);
	ASSERT(kill_calls == calls + 1 && !e->containment_pending && e->reacted,
	       "failed startup containment was not retried");
	PASS();
}

static void test_loss_during_containment(void)
{
	TEST("pending policy containment still checks log integrity on every sweep");
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(JOBD_FANOTIFY_DENY);
	ASSERT(e, "launch failed");
	kill_fails = 1;
	ASSERT(append_text("{\"alert\":true}\n") == 0, "write failed");
	handle_inotify();
	ASSERT(e->containment_pending && e->job.exit_reason == JOB_EXIT_POLICY,
	       "policy containment should be pending");
	ASSERT(replace_log() == 0, "cannot replace log");
	job_table_foreach(sweep_running, NULL);
	ASSERT(monitoring_failed(e, "device/inode") && e->containment_pending && !e->reacted,
	       "pending containment skipped log integrity checking");
	kill_fails = 0;
	job_table_foreach(sweep_running, NULL);
	ASSERT(!e->containment_pending && e->reacted &&
	       e->job.exit_reason == JOB_EXIT_INTERNAL, "retry lost the monitoring failure");
	PASS();
}

static void test_cleanup_pending(void)
{
	TEST("cleanup cannot discard a live job while containment is pending");
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(JOBD_FANOTIFY_DENY);
	ASSERT(e, "launch failed");
	kill_fails = 1;
	ASSERT(unlink(log_path) == 0, "unlink failed");
	handle_inotify();
	ASSERT(e->containment_pending, "containment should be pending");
	int sockets[2];
	ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "socketpair failed");
	struct jobd_msg_header hdr = {
		.magic = JOBD_PROTO_MAGIC, .version = JOBD_PROTO_VERSION,
		.type = JOBD_MSG_CLEANUP, .request_id = 43,
		.payload_len = (uint32_t)strlen(e->job.id),
	};
	ASSERT(jobd_send_msg(sockets[1], &hdr, (const uint8_t *)e->job.id) == 0,
	       "cannot send cleanup request");
	char response[RESP_BUF_BYTES];
	handle_request(sockets[0], response);
	struct jobd_response resp;
	uint8_t payload[1024];
	const uint8_t *data;
	size_t len;
	ASSERT(jobd_recv_msg(sockets[1], &hdr, payload, sizeof(payload), &len) == 0 &&
	       jobd_parse_response(payload, len, &resp, &data) == 0 &&
	       resp.status == JOBD_STATUS_ERR_INTERNAL, "cleanup reported success");
	close(sockets[0]);
	close(sockets[1]);
	ASSERT(job_table_find("monitored") == e && e->job.state == JOB_RUNNING &&
	       e->containment_pending && waitpid(child, NULL, WNOHANG) == 0,
	       "cleanup lost supervision of the live job");
	PASS();
}

static void test_backend_failure(int error, int overflow)
{
	TEST("overflow and backend read failure contain all running monitored jobs");
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(JOBD_FANOTIFY_DENY);
	ASSERT(e, "launch failed");
	handle_inotify();
	struct job job = e->job;
	snprintf(job.id, sizeof(job.id), "observe");
	job.fanotify_mode = JOBD_FANOTIFY_OBSERVE;
	struct job_entry *observe = job_table_add(&job);
	snprintf(job.id, sizeof(job.id), "off");
	job.fanotify_mode = JOBD_FANOTIFY_OFF;
	struct job_entry *off = job_table_add(&job);
	snprintf(job.id, sizeof(job.id), "finished");
	job.fanotify_mode = JOBD_FANOTIFY_DENY;
	job.state = JOB_EXITED;
	struct job_entry *finished = job_table_add(&job);
	ASSERT(observe && off && finished, "table add failed");
	if (overflow) {
		injected_event = (struct inotify_event){ .wd = -1, .mask = IN_Q_OVERFLOW };
		inject_event = 1;
	} else {
		inject(EVENTS, error, -1);
	}
	handle_inotify();
	ASSERT(kill_calls == 2 && e->monitor_failed && observe->monitor_failed &&
	       !off->monitor_failed && !finished->monitor_failed,
	       "backend failure did not cover exactly the running monitored jobs");
	ASSERT(e->job.exit_reason == JOB_EXIT_INTERNAL &&
	       observe->job.exit_reason == JOB_EXIT_INTERNAL, "backend failure lost internal reason");
	ASSERT(strstr(failure_cause, overflow ? "overflow" : "inotify read"),
	       "backend cause missing");
	if (!overflow) {
		char err[256];
		ASSERT(job_preflight(&e->job, err, sizeof(err)) != 0 &&
		       strstr(err, "monitored job"), "broken backend still accepts monitored launches");
	}
	PASS();
}

static int receive_result(int fd, uint64_t rid)
{
	struct jobd_msg_header hdr;
	struct jobd_response resp;
	uint8_t buf[1024];
	const uint8_t *data;
	size_t len;
	if (jobd_recv_msg(fd, &hdr, buf, sizeof(buf) - 1, &len) != 0 ||
	    jobd_parse_response(buf, len, &resp, &data) != 0)
		return 0;
	buf[len] = '\0';
	return hdr.request_id == rid && resp.status == JOBD_STATUS_OK &&
	       strstr((const char *)data, "state: FAILED\n") &&
	       strstr((const char *)data, "reason: INTERNAL\n");
}

static void test_final_failure(int fail_kill)
{
	TEST("final scan failure survives zero workload exit, persistence, and waiter responses");
	ASSERT(setup() == 0, "setup failed");
	struct job_entry *e = launch(JOBD_FANOTIFY_DENY);
	ASSERT(e, "launch failed");
	ASSERT(unlink(log_path) == 0, "unlink failed");
	FILE *result = fopen(result_path, "w");
	ASSERT(result, "cannot create cgroup result");
	fputs("exit=0 signal=0 oom_killed=0\n", result);
	ASSERT(fclose(result) == 0, "cannot save cgroup result");
	snprintf(e->result_path, sizeof(e->result_path), "%s", result_path);
	int sockets[2];
	ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "socketpair failed");
	e->waiters[0] = (struct job_waiter){ .fd = sockets[0], .request_id = 41 };
	e->waiter_count = 1;
	close(release_fd);
	release_fd = -1;
	int status;
	ASSERT(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
	       WEXITSTATUS(status) == 0, "workload did not exit zero");
	child = 0;
	kill_fails = fail_kill;
	job_finished(e, status);
	if (fail_kill) {
		ASSERT(e->job.state == JOB_RUNNING && e->containment_pending &&
		       e->waiter_count == 1 && e->log_wd >= 0,
		       "failed final containment prematurely finalized supervision");
		kill_fails = 0;
		job_table_foreach(sweep_running, NULL);
	}
	ASSERT(e->job.state == JOB_FAILED && e->job.exit_reason == JOB_EXIT_INTERNAL,
	       "zero exit overwrote monitoring failure");
	ASSERT(receive_result(sockets[1], 41), "waiting client received successful result");
	close(sockets[1]);
	struct job loaded;
	char err[256];
	ASSERT(job_state_load(e->job.id, &loaded, err, sizeof(err)) == 0,
	       "cannot load final persisted state");
	ASSERT(loaded.state == JOB_FAILED && loaded.exit_reason == JOB_EXIT_INTERNAL,
	       "persisted state lost internal failure");
	ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0, "socketpair failed");
	struct jobd_msg_header hdr = { .request_id = 42 };
	ASSERT(handle_wait(sockets[0], &hdr, e) == 0 && receive_result(sockets[1], 42),
	       "subsequent waiter received successful result");
	close(sockets[0]);
	close(sockets[1]);
	PASS();
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!mkdtemp(tmp))
		return 1;
	snprintf(log_dir, sizeof(log_dir), "%s/logs", tmp);
	snprintf(log_path, sizeof(log_path), "%s/logs/fanotifyd.jsonl", tmp);
	snprintf(moved_path, sizeof(moved_path), "%s/original.jsonl", tmp);
	snprintf(replacement, sizeof(replacement), "%s/replacement.jsonl", tmp);
	snprintf(result_path, sizeof(result_path), "%s/logs/cgroup.result", tmp);
	char err[256];
	if (mkdir(log_dir, 0700) != 0 ||
	    jobd_config_set("state_dir", tmp, err, sizeof(err)) != 0)
		return 1;
	test_replacement_event();
	teardown();
	test_replacement_sweep();
	teardown();
	test_sweep_without_watch();
	teardown();
	static const struct {
		enum loss_kind kind;
		const char *cause;
	} losses[] = {
		{ MISSING, "open alert log" },
		{ DIRECTORY, "not a regular file" },
		{ TRUNCATED, "truncated" },
		{ DEVICE, "device/inode" },
		{ UNREADABLE, "Permission denied" },
		{ WATCH_LOST, "watch lost" },
		{ DIRECTORY_MOVED, "watch lost" },
		{ UNMOUNTED, "watch lost" },
	};
	for (size_t i = 0; i < sizeof(losses) / sizeof(losses[0]); i++) {
		test_log_loss(losses[i].kind, JOBD_FANOTIFY_DENY, losses[i].cause);
		teardown();
	}
	test_log_loss(MISSING, JOBD_FANOTIFY_OBSERVE, "open alert log");
	teardown();
	test_io_failure(LOG_OPEN, EIO, 0, "open alert log");
	teardown();
	test_io_failure(LOG_STAT, EIO, 0, "stat alert log");
	teardown();
	test_io_failure(LOG_SEEK, EIO, 0, "seek alert log");
	teardown();
	test_io_failure(LOG_READ, EIO, 0, "read alert log");
	teardown();
	test_io_failure(LOG_READ, EIO, 1, "read alert log");
	teardown();
	for (enum fault_op op = LOG_OPEN; op <= EVENTS; op++) {
		test_eintr(op);
		teardown();
	}
	for (uint8_t mode = JOBD_FANOTIFY_OFF; mode <= JOBD_FANOTIFY_DENY; mode++) {
		test_modes(mode);
		teardown();
	}
	for (int fail_kill = 0; fail_kill <= 1; fail_kill++) {
		for (int events = 0; events <= 1; events++) {
			test_reaction_failure(fail_kill, events);
			teardown();
		}
		test_final_failure(fail_kill);
		teardown();
	}
	test_launch_failure(WATCH);
	teardown();
	test_launch_failure(LOG_OPEN);
	teardown();
	test_launch_failure(NO_FAULT);
	teardown();
	test_cleanup_pending();
	teardown();
	test_loss_during_containment();
	teardown();
	test_backend_failure(0, 1);
	teardown();
	test_backend_failure(EIO, 0);
	teardown();
	test_backend_failure(0, 0);
	teardown();
	rmdir(log_dir);
	char jobs[512];
	snprintf(jobs, sizeof(jobs), "%s/jobs", tmp);
	rmdir(jobs);
	rmdir(tmp);
	TEST_SUMMARY();
}
