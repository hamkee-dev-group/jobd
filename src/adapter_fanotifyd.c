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
	kill(pid, SIGKILL);
	int status;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
}

int job_fanotify_start(const struct job *job, struct job_sidecars *sc,
                         char *errmsg, size_t errmsg_sz)
{
	if (job->fanotify_mode == JOBD_FANOTIFY_OFF) {
		snprintf(errmsg, errmsg_sz, "fanotify disabled for this job");
		return 0;
	}

	const char *bin = jobd_component_path(JOBD_COMP_FANOTIFYD);
	if (!bin) {
		snprintf(errmsg, errmsg_sz, "fanotifyd not found");
		return -1;
	}

	if (jobd_job_subdir(job->id, "logs/fanotifyd.jsonl",
	                      sc->fanotify_log, sizeof(sc->fanotify_log)) != 0 ||
	    jobd_job_subdir(job->id, "fanotifyd.pid",
	                      sc->fanotify_pidfile,
	                      sizeof(sc->fanotify_pidfile)) != 0) {
		snprintf(errmsg, errmsg_sz, "fanotifyd paths too long");
		return -1;
	}

	unlink(sc->fanotify_log);
	unlink(sc->fanotify_pidfile);

	static char canary_paths[JOBD_MAX_CANARIES][JOBD_PATH_LEN_LONG];

	char *argv[16 + JOBD_MAX_CANARIES * 2];
	int argc = 0;

	argv[argc++] = (char *)bin;
	argv[argc++] = (char *)"-f";
	argv[argc++] = (char *)"--pid-file";
	argv[argc++] = sc->fanotify_pidfile;
	argv[argc++] = (char *)"--output";
	argv[argc++] = sc->fanotify_log;

	argv[argc++] = (char *)"--perm";
	if (job->fanotify_mode == JOBD_FANOTIFY_DENY)
		argv[argc++] = (char *)"--deny-on-alert";

	argv[argc++] = (char *)"--filesystem";
	argv[argc++] = (char *)job->root_path;

	for (uint32_t i = 0; i < job->canary_count && i < JOBD_MAX_CANARIES; i++) {
		int n = snprintf(canary_paths[i], JOBD_PATH_LEN_LONG, "%s%s",
		                 job->root_path, job->canaries[i]);
		if (n < 0 || (size_t)n >= JOBD_PATH_LEN_LONG)
			continue;
		argv[argc++] = (char *)"--canary";
		argv[argc++] = canary_paths[i];
	}

	argv[argc] = NULL;

	jobd_log("fanotifyd: starting for job %s (mode=%u, canaries=%u)",
	           job->id, job->fanotify_mode, job->canary_count);

	pid_t pid = fork();
	if (pid < 0) {
		snprintf(errmsg, errmsg_sz, "fanotifyd fork: %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		job_close_fds_above(STDERR_FILENO);
		char *env[] = { NULL };
		execve(argv[0], argv, env);
		_exit(127);
	}

	for (int i = 0; i < READY_ATTEMPTS; i++) {
		sleep_tick();
		if (access(sc->fanotify_pidfile, F_OK) == 0) {
			sc->fanotifyd_pid = pid;
			snprintf(errmsg, errmsg_sz, "fanotifyd ready (pid %d)", (int)pid);
			return 0;
		}

		int status;
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid) {
			snprintf(errmsg, errmsg_sz, "fanotifyd exited during startup");
			return -1;
		}
	}

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
