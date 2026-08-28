#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

		job_cgroup_freeze(jid, errmsg, errmsg_sz);
		e->job.exit_reason = JOB_EXIT_POLICY;
		if (job_cgroup_kill(jid, errmsg, errmsg_sz) != 0)
			return -1;
		snprintf(errmsg, errmsg_sz, "deny: job %s killed by policy", jid);
		return 0;

	case JOB_REACT_KILL:
		if (e->job.exit_reason == JOB_EXIT_NORMAL)
			e->job.exit_reason = JOB_EXIT_POLICY;
		if (job_cgroup_kill(jid, errmsg, errmsg_sz) != 0)
			return -1;
		snprintf(errmsg, errmsg_sz, "kill: job %s killed", jid);
		return 0;
	}

	snprintf(errmsg, errmsg_sz, "unhandled reaction");
	return -1;
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
	if (e->sc.fanotify_log[0] == '\0')
		return 0;
	if (e->job.fanotify_mode == JOBD_FANOTIFY_OFF)
		return 0;

	int fd = open(e->sc.fanotify_log, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;

	if (lseek(fd, (off_t)e->log_off, SEEK_SET) < 0) {
		close(fd);
		return 0;
	}

	char buf[8192];
	int  fired = 0;
	ssize_t got;

	while ((got = read(fd, buf, sizeof(buf) - 1)) > 0) {
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
			if (e->reacted)
				continue;

			e->reacted = 1;
			char err[256];
			job_react(e, JOB_REACT_DENY, err, sizeof(err));
			jobd_log("job %s: %s", e->job.id, err);
			fired = 1;
		}
	}

	close(fd);
	return fired;
}
