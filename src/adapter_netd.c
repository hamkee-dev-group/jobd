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

static void sleep_tick(void)
{
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000000L };
	nanosleep(&ts, NULL);
}

int job_netd_start(const struct job *job, struct job_sidecars *sc,
                     char *errmsg, size_t errmsg_sz)
{
	if (job->network_mode != JOBD_NETWORK_BROKERED) {
		snprintf(errmsg, errmsg_sz, "no brokered network for this job");
		return 0;
	}

	const char *bin = jobd_component_path(JOBD_COMP_JOB_NETD);
	if (!bin) {
		snprintf(errmsg, errmsg_sz, "job-netd not found");
		return -1;
	}

	int n = snprintf(sc->netd_sock, sizeof(sc->netd_sock),
	                 "%s/run/jobd/net.sock", job->root_path);
	if (n < 0 || (size_t)n >= (int)sizeof(sc->netd_sock)) {
		snprintf(errmsg, errmsg_sz, "network socket path too long");
		return -1;
	}
	unlink(sc->netd_sock);

	char *argv[8 + JOBD_MAX_ALLOW_NET * 2];
	int argc = 0;
	argv[argc++] = (char *)bin;
	argv[argc++] = (char *)"broker";
	argv[argc++] = (char *)"--socket";
	argv[argc++] = sc->netd_sock;

	for (uint32_t i = 0; i < job->allow_net_count; i++) {
		argv[argc++] = (char *)"--allow";
		argv[argc++] = (char *)job->allow_net[i];
	}
	argv[argc] = NULL;

	jobd_log("netd: starting broker for job %s (%u destination(s))",
	           job->id, job->allow_net_count);

	pid_t pid = fork();
	if (pid < 0) {
		snprintf(errmsg, errmsg_sz, "job-netd fork: %s", strerror(errno));
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
		if (access(sc->netd_sock, F_OK) == 0) {
			sc->netd_pid = pid;
			snprintf(errmsg, errmsg_sz,
			         "network broker ready (pid %d, %u destination(s))",
			         (int)pid, job->allow_net_count);
			return 0;
		}
		int status;
		if (waitpid(pid, &status, WNOHANG) == pid) {
			snprintf(errmsg, errmsg_sz,
			         "job-netd exited during startup");
			return -1;
		}
	}

	kill(pid, SIGKILL);
	int status;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
	snprintf(errmsg, errmsg_sz, "network broker socket was not created");
	return -1;
}

int job_netd_stop(struct job_sidecars *sc, char *errmsg, size_t errmsg_sz)
{
	if (sc->netd_pid <= 0) {
		snprintf(errmsg, errmsg_sz, "network broker not running");
		return 0;
	}

	pid_t pid = sc->netd_pid;
	sc->netd_pid = 0;

	jobd_log("netd: stopping broker pid %d", (int)pid);
	kill(pid, SIGTERM);

	int status;
	for (int i = 0; i < 20; i++) {
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid || (w < 0 && errno == ECHILD))
			goto done;
		sleep_tick();
	}

	kill(pid, SIGKILL);
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;

done:
	if (sc->netd_sock[0])
		unlink(sc->netd_sock);
	snprintf(errmsg, errmsg_sz, "network broker stopped");
	return 0;
}
