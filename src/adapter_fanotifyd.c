#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "jobd.h"

#define READY_ATTEMPTS 30
#define READY_INTERVAL_NS (100 * 1000000L)

static void sleep_tick(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = READY_INTERVAL_NS };
	nanosleep(&ts, NULL);
}

static void reap_failed(pid_t pid)
{
	if (pid <= 0)
		return;
	int status;
	pid_t w;
	do {
		w = waitpid(pid, &status, WNOHANG);
	} while (w < 0 && errno == EINTR);
	if (w != 0)
		return;
	kill(pid, SIGKILL);
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
}

static int pidfile_names(const char *path, pid_t pid)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
		return 0;

	/* The extra byte detects files exceeding the 128-byte limit. */
	char buf[129];
	size_t len = 0;
	ssize_t n = 0;
	while (len < sizeof(buf)) {
		n = read(fd, buf + len, sizeof(buf) - len);
		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0)
			break;
		len += (size_t)n;
	}
	close(fd);
	if (n != 0 || len == 0 || len >= sizeof(buf))
		return 0;
	buf[len] = '\0';
	if (buf[0] < '0' || buf[0] > '9')
		return 0;

	char *end;
	errno = 0;
	long value = strtol(buf, &end, 10);
	if (errno != 0 || value <= 0 || value != (long)pid)
		return 0;
	/* Check all bytes read, including any NUL that stopped strtol. */
	for (; end < buf + len; end++) {
		if (*end != ' ' && (*end < '\t' || *end > '\r'))
			return 0;
	}
	return 1;
}

static int enforcement_ready(int fd, pid_t pid, uint32_t canaries)
{
	/* fanotifyd's daemon_run emits this only after policy, marks and the
	 * event loop are installed. Its pidfile is written before loop setup. */
	char buf[4096], expected[160];
	ssize_t n;
	do {
		n = pread(fd, buf, sizeof(buf), 0);
	} while (n < 0 && errno == EINTR);
	if (n <= 0 || memchr(buf, '\0', (size_t)n))
		return 0;

	int len = snprintf(expected, sizeof(expected),
	                   " INFO  fanotifyd started (pid=%d) -- 1 mark(s), "
	                   "canaries=%u, burst=", (int)pid, canaries);
	char *msg = memmem(buf, (size_t)n, expected, (size_t)len);
	return msg && memchr(msg, '\n', (size_t)(buf + n - msg));
}

int job_fanotify_build_argv(const struct job *job, const char *bin,
                            const struct job_sidecars *sc, char *argv[],
                            int argv_max,
                            char canary_buf[][JOBD_PATH_LEN_LONG],
                            char *err, size_t err_sz)
{
	if (argv_max > 0)
		argv[0] = NULL;
	if (job->canary_count > JOBD_MAX_CANARIES) {
		snprintf(err, err_sz, "fanotifyd canary count %u exceeds %u",
		         job->canary_count, JOBD_MAX_CANARIES);
		return -1;
	}
	int slots = 10 + (job->fanotify_mode == JOBD_FANOTIFY_DENY) +
	            2 * (int)job->canary_count;
	if (argv_max < slots) {
		snprintf(err, err_sz, "fanotifyd argv buffer too small");
		return -1;
	}
	if (!bin || !*bin) {
		snprintf(err, err_sz, "fanotifyd not found");
		return -1;
	}
	for (uint32_t i = 0; i < job->canary_count; i++) {
		int n = snprintf(canary_buf[i], JOBD_PATH_LEN_LONG, "%s%s",
		                 job->root_path, job->canaries[i]);
		if (n < 0 || (size_t)n >= JOBD_PATH_LEN_LONG) {
			snprintf(err, err_sz, "fanotifyd canary %u path too long", i + 1);
			return -1;
		}
	}

	int argc = 0;
	argv[argc++] = (char *)bin;
	argv[argc++] = (char *)"-f";
	argv[argc++] = (char *)"--pid-file";
	argv[argc++] = (char *)sc->fanotify_pidfile;
	argv[argc++] = (char *)"--output";
	argv[argc++] = (char *)sc->fanotify_log;
	argv[argc++] = (char *)"--perm";
	if (job->fanotify_mode == JOBD_FANOTIFY_DENY)
		argv[argc++] = (char *)"--deny-on-alert";
	argv[argc++] = (char *)"--filesystem";
	argv[argc++] = (char *)job->root_path;
	for (uint32_t i = 0; i < job->canary_count; i++) {
		argv[argc++] = (char *)"--canary";
		argv[argc++] = canary_buf[i];
	}
	argv[argc] = NULL;
	return argc;
}

int job_fanotify_start(const struct job *job, struct job_sidecars *sc,
                         char *errmsg, size_t errmsg_sz)
{
	sc->fanotifyd_pid = 0;
	if (job->fanotify_mode == JOBD_FANOTIFY_OFF) {
		snprintf(errmsg, errmsg_sz, "fanotify disabled for this job");
		return 0;
	}

	const char *bin = jobd_component_path(JOBD_COMP_FANOTIFYD);
	char stderr_path[JOBD_PATH_LEN_LONG];
	if (jobd_job_subdir(job->id, "logs/fanotifyd.jsonl",
	                      sc->fanotify_log, sizeof(sc->fanotify_log)) != 0 ||
	    jobd_job_subdir(job->id, "fanotifyd.pid", sc->fanotify_pidfile,
	                      sizeof(sc->fanotify_pidfile)) != 0 ||
	    jobd_job_subdir(job->id, "logs/fanotifyd.stderr", stderr_path,
	                      sizeof(stderr_path)) != 0) {
		snprintf(errmsg, errmsg_sz, "fanotifyd paths too long");
		return -1;
	}

	char canary_paths[JOBD_MAX_CANARIES][JOBD_PATH_LEN_LONG];
	char *argv[16 + JOBD_MAX_CANARIES * 2];
	if (job_fanotify_build_argv(job, bin, sc, argv,
	                           (int)(sizeof(argv) / sizeof(argv[0])),
	                           canary_paths, errmsg, errmsg_sz) < 0)
		return -1;

	unlink(sc->fanotify_log);
	unlink(sc->fanotify_pidfile);
	int logfd = open(stderr_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (logfd < 0) {
		snprintf(errmsg, errmsg_sz, "fanotifyd startup log: %s", strerror(errno));
		return -1;
	}

	jobd_log("fanotifyd: starting for job %s (mode=%u, canaries=%u)",
	           job->id, job->fanotify_mode, job->canary_count);

	pid_t pid = fork();
	if (pid < 0) {
		snprintf(errmsg, errmsg_sz, "fanotifyd fork: %s", strerror(errno));
		close(logfd);
		return -1;
	}
	if (pid == 0) {
		if (dup2(logfd, STDERR_FILENO) < 0 ||
		    fcntl(STDERR_FILENO, F_SETFD, 0) < 0)
			_exit(127);
		job_close_fds_above(STDERR_FILENO);
		char *env[] = { NULL };
		execve(argv[0], argv, env);
		_exit(127);
	}

	for (int i = 0; i < READY_ATTEMPTS; i++) {
		sleep_tick();
		int ready = pidfile_names(sc->fanotify_pidfile, pid) &&
		            enforcement_ready(logfd, pid, job->canary_count);

		int status;
		pid_t w;
		do {
			w = waitpid(pid, &status, WNOHANG);
		} while (w < 0 && errno == EINTR);
		if (w == pid) {
			snprintf(errmsg, errmsg_sz, "fanotifyd exited during startup");
			close(logfd);
			return -1;
		}
		if (w < 0) {
			snprintf(errmsg, errmsg_sz, "fanotifyd waitpid: %s", strerror(errno));
			close(logfd);
			reap_failed(pid);
			return -1;
		}
		if (ready) {
			close(logfd);
			sc->fanotifyd_pid = pid;
			snprintf(errmsg, errmsg_sz, "fanotifyd ready (pid %d)", (int)pid);
			return 0;
		}
	}

	close(logfd);
	reap_failed(pid);
	snprintf(errmsg, errmsg_sz, "fanotifyd did not become ready");
	return -1;
}

int job_fanotify_stop(struct job_sidecars *sc, char *errmsg, size_t errmsg_sz)
{
	if (sc->fanotifyd_pid <= 0) {
		snprintf(errmsg, errmsg_sz, "fanotifyd not running");
		return 0;
	}

	pid_t pid = sc->fanotifyd_pid;
	sc->fanotifyd_pid = 0;

	jobd_log("fanotifyd: stopping pid %d", (int)pid);
	kill(pid, SIGTERM);

	int status;
	for (int i = 0; i < 20; i++) {
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid)
			goto done;
		if (w < 0 && errno == ECHILD)
			goto done;
		sleep_tick();
	}

	kill(pid, SIGKILL);
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

done:
	unlink(sc->fanotify_pidfile);
	snprintf(errmsg, errmsg_sz, "fanotifyd stopped");
	return 0;
}
