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

#include "jobd.h"

#define CGROUP_CALL_TIMEOUT_MS 15000

static int cgroupd_ready;

static int have_cgroupctl(const char **out, char *errmsg, size_t errmsg_sz)
{
	const char *ctl = jobd_component_path(JOBD_COMP_CGROUPCTL);
	if (!ctl) {
		snprintf(errmsg, errmsg_sz, "cgroupctl not found");
		return -1;
	}
	*out = ctl;
	return 0;
}

int job_cgroup_ensure_daemon(char *errmsg, size_t errmsg_sz)
{
	if (cgroupd_ready)
		return 0;

	const char *ctl;
	if (have_cgroupctl(&ctl, errmsg, errmsg_sz) != 0)
		return -1;

	const char *sock = jobd_paths()->cgroup_sock;

	char *ping[] = { (char *)ctl, (char *)"--socket", (char *)sock,
	                 (char *)"ping", NULL };
	struct job_spawn_out out;

	struct stat st;
	if (stat(sock, &st) == 0 && S_ISSOCK(st.st_mode)) {
		if (job_spawn(ping, NULL, NULL, CGROUP_CALL_TIMEOUT_MS,
		                &out) == 0) {
			cgroupd_ready = 1;
			return 0;
		}
	}

	const char *dmn = jobd_component_path(JOBD_COMP_CGROUPD);
	if (!dmn) {
		snprintf(errmsg, errmsg_sz,
		         "no cgroupd listening on %s and the cgroupd binary was "
		         "not found", sock);
		return -1;
	}

	const char *croot   = jobd_paths()->cgroup_root;
	const char *log_dir = jobd_paths()->cgroup_log_dir;
	mkdir(log_dir, 0700);

	pid_t p = fork();
	if (p < 0) {
		snprintf(errmsg, errmsg_sz, "fork: %s", strerror(errno));
		return -1;
	}
	if (p == 0) {
		mkdir(croot, 0755);
		job_close_fds_above(STDERR_FILENO);

		char *av[] = { (char *)dmn, (char *)"-r", (char *)croot,
		               (char *)"-s", (char *)sock,
		               (char *)"-L", (char *)log_dir, NULL };
		char *env[] = { NULL };
		execve(av[0], av, env);
		_exit(127);
	}

	for (int i = 0; i < 50; i++) {
		struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000000L };
		nanosleep(&ts, NULL);
		if (stat(sock, &st) == 0 && S_ISSOCK(st.st_mode))
			break;
	}

	if (job_spawn(ping, NULL, NULL, CGROUP_CALL_TIMEOUT_MS, &out) == 0) {
		cgroupd_ready = 1;
		return 0;
	}

	snprintf(errmsg, errmsg_sz, "cgroupd did not become ready on %s", sock);
	return -1;
}

static int parse_field(const char *text, const char *key, long *out)
{
	char pattern[64];
	int n = snprintf(pattern, sizeof(pattern), "%s:", key);
	if (n < 0 || (size_t)n >= sizeof(pattern))
		return -1;

	const char *p = text;
	while ((p = strstr(p, pattern))) {

		if (p != text && p[-1] != '\n') {
			p += n;
			continue;
		}
		p += n;
		while (*p == ' ' || *p == '\t')
			p++;
		char *end = NULL;
		errno = 0;
		long v = strtol(p, &end, 10);
		if (errno == 0 && end != p) {
			*out = v;
			return 0;
		}
		return -1;
	}
	return -1;
}

int job_cgroup_launch(const struct job *job, char *const child_av[],
                        char *const child_env[], pid_t *pid_out,
                        char *errmsg, size_t errmsg_sz)
{
	char err[512];
	if (job_cgroup_ensure_daemon(err, sizeof(err)) != 0) {
		snprintf(errmsg, errmsg_sz, "cgroupd: %s", err);
		return -1;
	}

	const char *ctl;
	if (have_cgroupctl(&ctl, errmsg, errmsg_sz) != 0)
		return -1;

	const char *sock = jobd_paths()->cgroup_sock;

	char mb[64], hb[64], pb[32], sb[64], cb[80];
	snprintf(mb, sizeof(mb), "%llu", (unsigned long long)job->memory_max);
	snprintf(hb, sizeof(hb), "%llu", (unsigned long long)job->memory_high);
	snprintf(pb, sizeof(pb), "%u", job->pids_max);
	snprintf(sb, sizeof(sb), "%llu", (unsigned long long)job->swap_max);
	snprintf(cb, sizeof(cb), "%llu %llu",
	         (unsigned long long)job->cpu_max_q,
	         (unsigned long long)job->cpu_max_p);

	#define CGROUP_AV_MAX (32 + 2 * (JOBD_MAX_ENV_COUNT + 16) + \
	                       16 + JOBD_MAX_ARGV + 1)
	char *av[CGROUP_AV_MAX];
	int ac = 0;
	av[ac++] = (char *)ctl;
	av[ac++] = (char *)"--socket";
	av[ac++] = (char *)sock;
	av[ac++] = (char *)"run";
	av[ac++] = (char *)"--id";
	av[ac++] = (char *)job->id;

	if (job->memory_max > 0)  { av[ac++] = (char *)"--memory-max";      av[ac++] = mb; }
	if (job->memory_high > 0) { av[ac++] = (char *)"--memory-high";     av[ac++] = hb; }
	if (job->pids_max > 0)    { av[ac++] = (char *)"--pids-max";        av[ac++] = pb; }
	if (job->swap_max > 0)    { av[ac++] = (char *)"--memory-swap-max"; av[ac++] = sb; }
	if (job->cpu_max_p > 0)   { av[ac++] = (char *)"--cpu-max";         av[ac++] = cb; }

	int env_count = 0;
	if (child_env) {
		for (int i = 0; child_env[i]; i++) {
			if (ac + 3 >= (int)CGROUP_AV_MAX) {
				snprintf(errmsg, errmsg_sz,
				         "too many environment entries for the "
				         "launch command line");
				return -1;
			}
			av[ac++] = (char *)"--env";
			av[ac++] = child_env[i];
			env_count++;
		}
	}

	av[ac++] = (char *)"--";
	for (int i = 0; child_av[i]; i++) {
		if (ac + 2 >= (int)CGROUP_AV_MAX) {
			snprintf(errmsg, errmsg_sz,
			         "launch command line too long");
			return -1;
		}
		av[ac++] = child_av[i];
	}
	av[ac] = NULL;
	#undef CGROUP_AV_MAX

	struct job_spawn_out out;
	int rc = job_spawn(av, NULL, NULL, CGROUP_CALL_TIMEOUT_MS, &out);
	if (rc != 0) {
		snprintf(errmsg, errmsg_sz, "cgroupctl run failed: %s",
		         out.stderr_buf[0] ? out.stderr_buf :
		         (out.stdout_buf[0] ? out.stdout_buf : "no output"));
		return -1;
	}
	if (!strstr(out.stdout_buf, "STATUS: ok")) {
		snprintf(errmsg, errmsg_sz, "cgroupctl run did not accept the job: %s",
		         out.stdout_buf[0] ? out.stdout_buf : "no output");
		return -1;
	}

	long pid = 0;
	if (parse_field(out.stdout_buf, "pid", &pid) != 0 || pid <= 0) {
		snprintf(errmsg, errmsg_sz,
		         "cgroupctl run did not report a pid");
		return -1;
	}

	if (pid_out)
		*pid_out = (pid_t)pid;

	snprintf(errmsg, errmsg_sz, "submitted (workload pid %ld, %d env entries)",
	         pid, env_count);
	return 0;
}

int job_cgroup_start_waiter(const char *jid, const char *result_path,
                              pid_t *pid_out, char *errmsg, size_t errmsg_sz)
{
	const char *ctl;
	if (have_cgroupctl(&ctl, errmsg, errmsg_sz) != 0)
		return -1;

	const char *sock = jobd_paths()->cgroup_sock;

	pid_t p = fork();
	if (p < 0) {
		snprintf(errmsg, errmsg_sz, "fork: %s", strerror(errno));
		return -1;
	}

	if (p == 0) {
		int fd = open(result_path,
		              O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0640);
		if (fd >= 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
		job_close_fds_above(STDERR_FILENO);

		char *av[] = { (char *)ctl, (char *)"--socket", (char *)sock,
		               (char *)"wait", (char *)jid, NULL };
		char *env[] = { NULL };
		execve(av[0], av, env);
		_exit(127);
	}

	if (pid_out)
		*pid_out = p;
	snprintf(errmsg, errmsg_sz, "waiter pid %d", (int)p);
	return 0;
}

int job_cgroup_read_result(const char *result_path, uint32_t *exit_code,
                             uint32_t *exit_signal, int *oom_killed)
{
	int fd = open(result_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return -1;

	char text[4096];
	ssize_t n = read(fd, text, sizeof(text) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	text[n] = '\0';

	long v;
	int found = 0;

	if (parse_field(text, "exit", &v) == 0 && v >= 0) {
		*exit_code = (uint32_t)v;
		found = 1;
	}
	if (parse_field(text, "signal", &v) == 0 && v >= 0) {
		*exit_signal = (uint32_t)v;
		found = 1;
	}
	if (parse_field(text, "oom_killed", &v) == 0)
		*oom_killed = v != 0;

	return found ? 0 : -1;
}

static int simple_cgroup_cmd(const char *jid, const char *cmd,
                             char *errmsg, size_t errmsg_sz)
{
	const char *ctl;
	if (have_cgroupctl(&ctl, errmsg, errmsg_sz) != 0)
		return -1;

	const char *sock = jobd_paths()->cgroup_sock;
	char *av[] = { (char *)ctl, (char *)"--socket", (char *)sock,
	               (char *)cmd, (char *)jid, NULL };

	struct job_spawn_out out;
	int rc = job_spawn(av, NULL, NULL, CGROUP_CALL_TIMEOUT_MS, &out);
	if (rc != 0) {
		snprintf(errmsg, errmsg_sz, "cgroupctl %s: %s", cmd,
		         out.stderr_buf[0] ? out.stderr_buf : "failed");
		return -1;
	}

	snprintf(errmsg, errmsg_sz, "%s ok", cmd);
	return 0;
}

int job_cgroup_kill(const char *jid, char *errmsg, size_t errmsg_sz)
{
	return simple_cgroup_cmd(jid, "kill", errmsg, errmsg_sz);
}

int job_cgroup_freeze(const char *jid, char *errmsg, size_t errmsg_sz)
{
	return simple_cgroup_cmd(jid, "freeze", errmsg, errmsg_sz);
}

int job_cgroup_remove(const char *jid, char *errmsg, size_t errmsg_sz)
{

	simple_cgroup_cmd(jid, "remove", errmsg, errmsg_sz);
	snprintf(errmsg, errmsg_sz, "removed");
	return 0;
}
