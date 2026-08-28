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

static void reap(pid_t pid)
{
	if (pid <= 0)
		return;
	kill(pid, SIGKILL);
	int status;
	while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
		;
}

int job_iouringd_start(const struct job *job, struct job_sidecars *sc,
                         uint32_t seq, char *errmsg, size_t errmsg_sz)
{
	if (!job->iouring_enabled) {
		snprintf(errmsg, errmsg_sz, "iouringd disabled for this job");
		return 0;
	}

	const char *bin = jobd_component_path(JOBD_COMP_IOURINGD);
	if (!bin) {
		snprintf(errmsg, errmsg_sz, "iouringd not found");
		return -1;
	}

	int n = snprintf(sc->iouringd_sock, sizeof(sc->iouringd_sock),
	                 "%s/run/jobd/iouringd.sock", job->root_path);
	if (n < 0 || (size_t)n >= (int)sizeof(sc->iouringd_sock)) {
		snprintf(errmsg, errmsg_sz, "iouringd socket path too long");
		return -1;
	}
	unlink(sc->iouringd_sock);

	char seq_buf[32];
	snprintf(seq_buf, sizeof(seq_buf), "%u", seq);

	char *argv[] = {
		(char *)bin,
		(char *)"--ring-entries",       (char *)JOBD_IOURING_RING_ENTRIES,
		(char *)"--max-clients",        (char *)JOBD_IOURING_MAX_CLIENTS,
		(char *)"--per-client-credits", (char *)JOBD_IOURING_CREDITS,
		(char *)"--io-bytes-max",       (char *)JOBD_IOURING_IO_BYTES_MAX,
		(char *)"--job-id",             seq_buf,
		sc->iouringd_sock,
		NULL
	};

	jobd_log("iouringd: starting for job %s (numeric id %u)", job->id, seq);

	pid_t pid = fork();
	if (pid < 0) {
		snprintf(errmsg, errmsg_sz, "iouringd fork: %s", strerror(errno));
		return -1;
	}
	if (pid == 0) {
		job_close_fds_above(STDERR_FILENO);
		char *env[] = { NULL };
		execve(argv[0], argv, env);
		_exit(127);
	}

	int ready = 0;
	for (int i = 0; i < READY_ATTEMPTS; i++) {
		sleep_tick();
		if (access(sc->iouringd_sock, F_OK) == 0) {
			ready = 1;
			break;
		}
		int status;
		if (waitpid(pid, &status, WNOHANG) == pid) {
			snprintf(errmsg, errmsg_sz, "iouringd exited during startup");
			return -1;
		}
	}

	if (!ready) {
		reap(pid);
		snprintf(errmsg, errmsg_sz, "iouringd socket was not created");
		return -1;
	}

	sc->iouringd_pid = pid;
	snprintf(errmsg, errmsg_sz, "iouringd ready (pid %d)", (int)pid);
	return 0;
}

int job_iouringd_stop(struct job_sidecars *sc, char *errmsg, size_t errmsg_sz)
{
	if (sc->iouringd_pid <= 0) {
		snprintf(errmsg, errmsg_sz, "iouringd not running");
		return 0;
	}

	pid_t pid = sc->iouringd_pid;
	sc->iouringd_pid = 0;

	jobd_log("iouringd: stopping pid %d", (int)pid);
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
	if (sc->iouringd_sock[0])
		unlink(sc->iouringd_sock);
	snprintf(errmsg, errmsg_sz, "iouringd stopped");
	return 0;
}
