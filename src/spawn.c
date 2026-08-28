#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#include "jobd.h"

#define SPAWN_MAX_ARGS 256

void job_close_fds_above(int keep_max)
{
#if defined(__NR_close_range)
	if (syscall(__NR_close_range, (unsigned int)(keep_max + 1),
	            ~0U, 0) == 0)
		return;
#endif

	DIR *d = opendir("/proc/self/fd");
	if (d) {
		int dfd = dirfd(d);
		struct dirent *ent;
		while ((ent = readdir(d))) {
			if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
				continue;
			int fd = atoi(ent->d_name);
			if (fd > keep_max && fd != dfd)
				close(fd);
		}
		closedir(d);
		return;
	}

	long max_fd = sysconf(_SC_OPEN_MAX);
	if (max_fd < 0 || max_fd > 1048576)
		max_fd = 1048576;
	for (int fd = keep_max + 1; fd < (int)max_fd; fd++)
		close(fd);
}

static long elapsed_ms(const struct timespec *start)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000L +
	       (now.tv_nsec - start->tv_nsec) / 1000000L;
}

static void sink_append(char *buf, size_t buf_sz, size_t *used,
                        const char *data, size_t n)
{
	if (*used + 1 >= buf_sz)
		return;
	size_t room = buf_sz - 1 - *used;
	if (n > room)
		n = room;
	memcpy(buf + *used, data, n);
	*used += n;
	buf[*used] = '\0';
}

static int do_spawn(char *const av[], char *const env[], const char *wd,
                    int timeout_ms, struct job_spawn_out *r)
{
	memset(r, 0, sizeof(*r));

	int op[2] = {-1, -1}, ep[2] = {-1, -1};
	if (pipe2(op, O_CLOEXEC) != 0) {
		snprintf(r->errmsg, sizeof(r->errmsg), "pipe: %s", strerror(errno));
		return -1;
	}
	if (pipe2(ep, O_CLOEXEC) != 0) {
		snprintf(r->errmsg, sizeof(r->errmsg), "pipe: %s", strerror(errno));
		close(op[0]); close(op[1]);
		return -1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		snprintf(r->errmsg, sizeof(r->errmsg), "fork: %s", strerror(errno));
		close(op[0]); close(op[1]); close(ep[0]); close(ep[1]);
		return -1;
	}

	if (pid == 0) {
		if (wd && chdir(wd) != 0)
			_exit(127);
		if (dup2(op[1], STDOUT_FILENO) < 0 || dup2(ep[1], STDERR_FILENO) < 0)
			_exit(127);
		job_close_fds_above(STDERR_FILENO);
		if (env)
			execve(av[0], av, env);
		else
			execv(av[0], av);
		_exit(127);
	}

	close(op[1]);
	close(ep[1]);

	struct timespec start;
	clock_gettime(CLOCK_MONOTONIC, &start);

	size_t out_used = 0, err_used = 0;
	struct pollfd pfd[2] = {
		{ .fd = op[0], .events = POLLIN },
		{ .fd = ep[0], .events = POLLIN },
	};
	int open_count = 2;

	while (open_count > 0) {
		int wait_ms = 200;
		if (timeout_ms > 0) {
			long left = timeout_ms - elapsed_ms(&start);
			if (left <= 0) {
				r->timed_out = 1;
				break;
			}
			if (left < wait_ms)
				wait_ms = (int)left;
		}

		int n = poll(pfd, 2, wait_ms);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		for (int i = 0; i < 2; i++) {
			if (pfd[i].fd < 0 || !pfd[i].revents)
				continue;

			if (pfd[i].revents & POLLIN) {
				char chunk[4096];
				ssize_t got = read(pfd[i].fd, chunk, sizeof(chunk));
				if (got > 0) {
					if (i == 0)
						sink_append(r->stdout_buf,
						            sizeof(r->stdout_buf),
						            &out_used, chunk, (size_t)got);
					else
						sink_append(r->stderr_buf,
						            sizeof(r->stderr_buf),
						            &err_used, chunk, (size_t)got);
					continue;
				}
				if (got < 0 && (errno == EINTR || errno == EAGAIN))
					continue;
			}

			close(pfd[i].fd);
			pfd[i].fd = -1;
			open_count--;
		}
	}

	for (int i = 0; i < 2; i++) {
		if (pfd[i].fd >= 0)
			close(pfd[i].fd);
	}

	int status = 0;
	while (1) {
		pid_t w = waitpid(pid, &status, r->timed_out ? WNOHANG : 0);
		if (w < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (w == 0) {
			if (timeout_ms > 0 && elapsed_ms(&start) >= timeout_ms) {
				r->timed_out = 1;
				kill(pid, SIGKILL);
				while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
					;
				break;
			}
			struct timespec ts = { .tv_sec = 0, .tv_nsec = 20 * 1000000L };
			nanosleep(&ts, NULL);
			continue;
		}
		break;
	}

	if (WIFEXITED(status))
		r->exit_code = WEXITSTATUS(status);
	else if (WIFSIGNALED(status))
		r->exit_signal = WTERMSIG(status);

	return 0;
}

int job_spawn(char *const av[], char *const env[], const char *wd,
                int timeout_ms, struct job_spawn_out *out)
{
	struct job_spawn_out local;
	struct job_spawn_out *r = out ? out : &local;

	if (do_spawn(av, env, wd, timeout_ms, r) != 0)
		return -1;
	if (r->timed_out)
		return -1;
	return r->exit_code == 0 && r->exit_signal == 0 ? 0 : 1;
}

int job_spawn_simple(int timeout_ms, const char *path, ...)
{
	char *av[SPAWN_MAX_ARGS];
	int ac = 0;

	av[ac++] = (char *)path;

	va_list ap;
	va_start(ap, path);
	while (ac < SPAWN_MAX_ARGS - 1) {
		char *a = va_arg(ap, char *);
		if (!a)
			break;
		av[ac++] = a;
	}
	va_end(ap);
	av[ac] = NULL;

	return job_spawn(av, NULL, NULL, timeout_ms, NULL);
}
