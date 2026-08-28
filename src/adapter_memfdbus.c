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
#define PUT_TIMEOUT_MS 30000

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

int job_memfdbus_start(const struct job *job, struct job_sidecars *sc,
                         char *errmsg, size_t errmsg_sz)
{
	if (job->memfd_input_count == 0) {
		snprintf(errmsg, errmsg_sz, "no memfd inputs, skipping");
		return 0;
	}

	const char *bin = jobd_component_path(JOBD_COMP_MEMFDBUS);
	if (!bin) {
		snprintf(errmsg, errmsg_sz, "memfdbus not found");
		return -1;
	}

	int n = snprintf(sc->memfdbus_sock, sizeof(sc->memfdbus_sock),
	                 "%s/run/jobd/memfdbus.sock", job->root_path);
	if (n < 0 || (size_t)n >= (int)sizeof(sc->memfdbus_sock)) {
		snprintf(errmsg, errmsg_sz, "memfdbus socket path too long");
		return -1;
	}
	unlink(sc->memfdbus_sock);

	char *argv[] = {
		(char *)bin, (char *)"broker",
		(char *)"--socket",      sc->memfdbus_sock,
		(char *)"--max-objects", (char *)"64",
		(char *)"--max-clients", (char *)"4",
		NULL
	};

	jobd_log("memfdbus: starting broker for job %s", job->id);

	pid_t pid = fork();
	if (pid < 0) {
		snprintf(errmsg, errmsg_sz, "memfdbus fork: %s", strerror(errno));
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
		if (access(sc->memfdbus_sock, F_OK) == 0) {
			ready = 1;
			break;
		}
		int status;
		if (waitpid(pid, &status, WNOHANG) == pid) {
			snprintf(errmsg, errmsg_sz, "memfdbus exited during startup");
			return -1;
		}
	}

	if (!ready) {
		reap(pid);
		snprintf(errmsg, errmsg_sz, "memfdbus socket was not created");
		return -1;
	}

	sc->memfdbus_pid = pid;

	for (uint32_t i = 0; i < job->memfd_input_count; i++) {
		char *pub[] = {
			(char *)bin, (char *)"put",
			(char *)job->memfd_inputs[i].path,
			(char *)"--name",     (char *)job->memfd_inputs[i].name,
			(char *)"--job-id",   (char *)job->id,
			(char *)"--allow-job", (char *)job->id,
			(char *)"--socket",   sc->memfdbus_sock,
			NULL
		};

		struct job_spawn_out out;
		if (job_spawn(pub, NULL, NULL, PUT_TIMEOUT_MS, &out) != 0) {
			snprintf(errmsg, errmsg_sz,
			         "memfdbus put %s failed: %s",
			         job->memfd_inputs[i].name,
			         out.stderr_buf[0] ? out.stderr_buf : "unknown error");
			job_memfdbus_stop(sc, errmsg, errmsg_sz);
			snprintf(errmsg, errmsg_sz, "memfdbus put %s failed",
			         job->memfd_inputs[i].name);
			return -1;
		}
		jobd_log("memfdbus: published %s", job->memfd_inputs[i].name);
	}

	snprintf(errmsg, errmsg_sz, "memfdbus ready (pid %d, %u objects)",
	         (int)pid, job->memfd_input_count);
	return 0;
}

int job_memfdbus_stop(struct job_sidecars *sc, char *errmsg, size_t errmsg_sz)
{
	if (sc->memfdbus_pid <= 0) {
		snprintf(errmsg, errmsg_sz, "memfdbus not running");
		return 0;
	}

	pid_t pid = sc->memfdbus_pid;
	sc->memfdbus_pid = 0;

	jobd_log("memfdbus: stopping pid %d", (int)pid);
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
	if (sc->memfdbus_sock[0])
		unlink(sc->memfdbus_sock);
	snprintf(errmsg, errmsg_sz, "memfdbus stopped");
	return 0;
}
