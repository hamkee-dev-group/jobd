#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "jobd.h"
#include "state.h"

int job_react(struct job_entry *e, enum job_react_action action,
                char *errmsg, size_t errmsg_sz)
{
	static const char *names[] = { "observe", "deny", "freeze", "kill" };
	const char *jid = e->job.id;

	if (action < JOB_REACT_OBSERVE || action > JOB_REACT_KILL) {
		snprintf(errmsg, errmsg_sz, "unknown reaction %d", (int)action);
		return -1;
	}

	jobd_log_event(jid, "jobd", "policy_react", names[action]);

	switch (action) {
	case JOB_REACT_OBSERVE:
		snprintf(errmsg, errmsg_sz, "observe: job %s event recorded", jid);
		return 0;

	case JOB_REACT_FREEZE:
		if (job_cgroup_freeze(jid, errmsg, errmsg_sz) != 0)
			return -1;
		snprintf(errmsg, errmsg_sz, "freeze: job %s frozen", jid);
		return 0;

	case JOB_REACT_DENY:
		e->containment_pending = 1;
		e->reacted = 0;
		if (job_cgroup_freeze(jid, errmsg, errmsg_sz) != 0)
			jobd_log("job %s: freeze failed: %s; attempting kill",
			         jid, errmsg);
		if (e->job.exit_reason != JOB_EXIT_INTERNAL)
			e->job.exit_reason = JOB_EXIT_POLICY;
		if (job_cgroup_kill(jid, errmsg, errmsg_sz) != 0)
			return -1;
		e->containment_pending = 0;
		e->reacted = 1;
		snprintf(errmsg, errmsg_sz, "deny: job %s killed by policy", jid);
		return 0;

	case JOB_REACT_KILL:
		e->containment_pending = 1;
		e->reacted = 0;
		if (e->job.exit_reason == JOB_EXIT_NORMAL)
			e->job.exit_reason = JOB_EXIT_POLICY;
		if (job_cgroup_kill(jid, errmsg, errmsg_sz) != 0)
			return -1;
		e->containment_pending = 0;
		e->reacted = 1;
		snprintf(errmsg, errmsg_sz, "kill: job %s killed", jid);
		return 0;
	}

	snprintf(errmsg, errmsg_sz, "unhandled reaction");
	return -1;
}

static int contain(struct job_entry *e, enum job_react_action action)
{
	char err[256];
	int rc = job_react(e, action, err, sizeof(err));
	jobd_log("job %s: %s%s", e->job.id,
	         rc != 0 ? "containment failed: " : "", err);
	return rc != 0 ? -1 : 1;
}

int job_monitor_fail(struct job_entry *e, const char *cause)
{
	if (e->job.fanotify_mode == JOBD_FANOTIFY_OFF)
		return 0;
	if (!e->monitor_failed) {
		jobd_log("job %s: monitoring failed: %s", e->job.id, cause);
		jobd_log_event(e->job.id, "jobd", "monitor_failed", cause);
		e->monitor_failed = 1;
	}
	e->job.exit_reason = JOB_EXIT_INTERNAL;
	if (!e->reacted)
		contain(e, JOB_REACT_KILL);
	return -1;
}

static int monitor_errno(struct job_entry *e, const char *operation)
{
	char cause[256];
	snprintf(cause, sizeof(cause), "%s alert log: %s", operation,
	         strerror(errno));
	return job_monitor_fail(e, cause);
}

static int check_log(struct job_entry *e, int fd, int establish)
{
	struct stat st;
	int rc;
	do {
		rc = fstat(fd, &st);
	} while (rc < 0 && errno == EINTR);
	if (rc < 0)
		return monitor_errno(e, "stat");
	if (!S_ISREG(st.st_mode))
		return job_monitor_fail(e, "alert log is not a regular file");
	if (establish) {
		e->log_dev = st.st_dev;
		e->log_ino = st.st_ino;
		e->log_identity_set = 1;
	} else if (st.st_dev != e->log_dev || st.st_ino != e->log_ino) {
		return job_monitor_fail(e, "alert log device/inode changed");
	}
	if (st.st_size < (off_t)e->log_off)
		return job_monitor_fail(e, "alert log truncated below consumed offset");
	return 0;
}

static int open_log(struct job_entry *e)
{
	int fd;
	do {
		fd = open(e->sc.fanotify_log,
		          O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	} while (fd < 0 && errno == EINTR);
	if (fd < 0)
		monitor_errno(e, "open");
	return fd;
}

int job_monitor_start(struct job_entry *e)
{
	if (e->job.fanotify_mode == JOBD_FANOTIFY_OFF)
		return 0;
	int fd = open_log(e);
	if (fd < 0)
		return -1;
	int rc = check_log(e, fd, !e->log_identity_set);
	close(fd);
	return rc;
}

static int line_is_alert(const char *line)
{
	return strstr(line, "\"alert\"")   != NULL ||
	       strstr(line, "\"canary\"")  != NULL ||
	       strstr(line, "\"denied\"")  != NULL ||
	       strstr(line, "\"violation\"") != NULL;
}

int job_monitor_scan_alerts(struct job_entry *e)
{
	int fired = 0;
	if (e->containment_pending)
		fired = contain(e, JOB_REACT_KILL);
	if (e->job.fanotify_mode == JOBD_FANOTIFY_OFF)
		return fired;
	if (e->monitor_failed)
		return -1;
	if (!e->log_identity_set)
		return job_monitor_fail(e, "alert log identity was not established");

	int fd = open_log(e);
	if (fd < 0)
		return -1;
	if (check_log(e, fd, 0) != 0) {
		close(fd);
		return -1;
	}

	off_t pos;
	do {
		pos = lseek(fd, (off_t)e->log_off, SEEK_SET);
	} while (pos < 0 && errno == EINTR);
	if (pos < 0) {
		monitor_errno(e, "seek");
		close(fd);
		return -1;
	}

	char buf[8192];
	ssize_t got;

	for (;;) {
		got = read(fd, buf, sizeof(buf) - 1);
		if (got < 0 && errno == EINTR)
			continue;
		if (got < 0) {
			monitor_errno(e, "read");
			fired = -1;
			break;
		}
		if (got == 0) {
			if (check_log(e, fd, 0) != 0)
				fired = -1;
			break;
		}
		buf[got] = '\0';
		e->log_off += (long)got;

		char *save = NULL;
		for (char *line = strtok_r(buf, "\n", &save); line;
		     line = strtok_r(NULL, "\n", &save)) {
			if (!line_is_alert(line))
				continue;

			jobd_log_event(e->job.id, "fanotifyd", "alert", line);

			if (e->job.fanotify_mode != JOBD_FANOTIFY_DENY)
				continue;
			if (e->reacted || e->containment_pending)
				continue;

			fired = contain(e, JOB_REACT_DENY);
		}
	}

	close(fd);
	return fired;
}
