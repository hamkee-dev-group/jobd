#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>

#include "jobd.h"
#include "state.h"

#define ENV_BUF_BYTES (JOBD_ENV_BYTES + 2048)
#define MAX_ENV_SLOTS (JOBD_MAX_ENV_COUNT + 16)

static int sys_pidfd_open(pid_t pid)
{
#ifdef __NR_pidfd_open
	return (int)syscall(__NR_pidfd_open, pid, 0);
#else
	(void)pid;
	errno = ENOSYS;
	return -1;
#endif
}

static int key_len(const char *entry)
{
	const char *eq = strchr(entry, '=');
	return eq ? (int)(eq - entry) : (int)strlen(entry);
}

int job_build_launch_env(const struct job *job,
                           char *buf, size_t buf_sz,
                           char **out, int out_max,
                           char *err, size_t err_sz)
{
	size_t used = 0;
	int    n    = 0;

	#define ENV_PUT(entry)                                                \
		do {                                                          \
			const char *_e = (entry);                             \
			int _kl = key_len(_e);                                \
			int _slot = -1;                                       \
			for (int _j = 0; _j < n; _j++) {                      \
				if (key_len(out[_j]) == _kl &&                \
				    strncmp(out[_j], _e, (size_t)_kl) == 0) { \
					_slot = _j;                           \
					break;                                \
				}                                             \
			}                                                     \
			if (_slot < 0 && n >= out_max - 1) {                  \
				snprintf(err, err_sz,                         \
				         "too many environment entries");     \
				return -1;                                    \
			}                                                     \
			size_t _len = strlen(_e);                             \
			if (_len + 1 > buf_sz - used) {                       \
				snprintf(err, err_sz, "environment too large"); \
				return -1;                                    \
			}                                                     \
			memcpy(buf + used, _e, _len + 1);                     \
			if (_slot >= 0)                                       \
				out[_slot] = buf + used;                      \
			else                                                  \
				out[n++] = buf + used;                        \
			used += _len + 1;                                     \
		} while (0)

	char scratch[JOBD_MAX_ENV_LEN];

	ENV_PUT("PATH=/usr/bin:/bin");
	ENV_PUT("HOME=/workspace");
	ENV_PUT("TMPDIR=/tmp");
	ENV_PUT("LANG=C.UTF-8");

	snprintf(scratch, sizeof(scratch), "JOBD_JOB_ID=%s", job->id);
	ENV_PUT(scratch);

	if (job->memfd_input_count > 0)
		ENV_PUT("MEMFDBUS_SOCKET=/run/jobd/memfdbus.sock");
	if (job->iouring_enabled)
		ENV_PUT("IOURINGD_SOCKET=/run/jobd/iouringd.sock");

	if (job->network_mode == JOBD_NETWORK_BROKERED) {
		snprintf(scratch, sizeof(scratch),
		         "ALL_PROXY=socks5h://127.0.0.1:%d", JOBD_BROKER_PORT);
		ENV_PUT(scratch);
		snprintf(scratch, sizeof(scratch),
		         "all_proxy=socks5h://127.0.0.1:%d", JOBD_BROKER_PORT);
		ENV_PUT(scratch);
		snprintf(scratch, sizeof(scratch),
		         "JOBD_SOCKS_PROXY=127.0.0.1:%d", JOBD_BROKER_PORT);
		ENV_PUT(scratch);
	}

	size_t off = 0;
	for (uint32_t i = 0; i < job->envc && off < job->env_bytes; i++) {
		const char *entry = job->env_buf + off;
		off += strlen(entry) + 1;
		ENV_PUT(entry);
	}

	#undef ENV_PUT

	out[n] = NULL;
	return n;
}

struct rollback {
	int netd;
	int overlay;
	int rootfs;
	int fanotify;
	int memfdbus;
	int iouringd;
};

static void rollback_unwind(struct job_entry *e, const struct rollback *rb)
{
	char err[256];

	if (rb->netd)
		job_netd_stop(&e->sc, err, sizeof(err));
	if (rb->iouringd)
		job_iouringd_stop(&e->sc, err, sizeof(err));
	if (rb->memfdbus)
		job_memfdbus_stop(&e->sc, err, sizeof(err));
	if (rb->fanotify)
		job_fanotify_stop(&e->sc, err, sizeof(err));
	if (rb->overlay || rb->rootfs)
		job_cleanup_job(e);
}

static int make_job_dirs(const struct job *job, char *err, size_t err_sz)
{
	const char *runtime = jobd_paths()->runtime_dir;

	int dirfd = open(runtime, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0) {
		snprintf(err, err_sz, "cannot open %s: %s", runtime,
		         strerror(errno));
		return -1;
	}

	if (mkdirat(dirfd, job->id, 0700) < 0 && errno != EEXIST) {
		snprintf(err, err_sz, "cannot create the job directory: %s",
		         strerror(errno));
		close(dirfd);
		return -1;
	}
	close(dirfd);

	static const char *subs[] = { "logs", "policy", "sockets", NULL };
	for (int i = 0; subs[i]; i++) {
		char p[JOBD_PATH_LEN_LONG];
		if (jobd_job_subdir(job->id, subs[i], p, sizeof(p)) != 0) {
			snprintf(err, err_sz, "job path too long");
			return -1;
		}
		if (mkdir(p, 0700) < 0 && errno != EEXIST) {
			snprintf(err, err_sz, "cannot create %.512s: %s", p,
			         strerror(errno));
			return -1;
		}
	}

	return 0;
}

int job_launch(struct job_entry *e, struct agd_buf *out)
{
	struct job *job = &e->job;
	struct rollback rb = { 0 };
	char err[1024];

	agd_buf_addf(out, "=== job: %s ===\n", job->id);

	char display[4096];
	job_argv_display(job, display, sizeof(display));
	jobd_log("execute: job=%s argv=%s", job->id, display);

	if (jobd_job_subdir(job->id, "root",
	                      job->root_path, sizeof(job->root_path)) != 0 ||
	    jobd_job_subdir(job->id, "root/export",
	                      job->export_path, sizeof(job->export_path)) != 0 ||
	    jobd_job_subdir(job->id, "root/run/jobd/landlock.toml",
	                      job->policy_path, sizeof(job->policy_path)) != 0 ||
	    jobd_job_subdir(job->id, "logs",
	                      job->log_dir, sizeof(job->log_dir)) != 0) {
		agd_buf_adds(out, "FAIL: job paths too long\n");
		job->state = JOB_FAILED;
		job->exit_reason = JOB_EXIT_SETUP;
		return -1;
	}

	agd_buf_adds(out, "step0 preflight...\n");
	if (job_preflight(job, err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL preflight: %s\n", err);
		job->state = JOB_FAILED;
		job->exit_reason = JOB_EXIT_SETUP;
		return -1;
	}
	agd_buf_adds(out, "  ok\n");

	if (make_job_dirs(job, err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL job directories: %s\n", err);
		job->state = JOB_FAILED;
		job->exit_reason = JOB_EXIT_SETUP;
		return -1;
	}

	agd_buf_adds(out, "step1 overlay workspace...\n");
	if (job_overlay_ensure_store(err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL overlay store: %s\n", err);
		goto fail;
	}
	if (job_overlay_create_ws(job, err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL overlay workspace: %s\n", err);
		goto fail;
	}
	rb.overlay = 1;
	agd_buf_addf(out, "  %s\n", err);

	agd_buf_adds(out, "step2 rootfs...\n");
	if (job_rootfs_prepare(job, err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL rootfs: %s\n", err);
		goto fail;
	}
	rb.rootfs = 1;
	job->state = JOB_ROOTFS_READY;
	agd_buf_adds(out, "  ok\n");

	agd_buf_adds(out, "step3 policy...\n");
	if (job_landlock_generate_policy(job, job->policy_path,
	                                   err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL policy: %s\n", err);
		goto fail;
	}
	agd_buf_adds(out, "  ok\n");

	agd_buf_adds(out, "step4 fanotifyd...\n");
	if (job_fanotify_start(job, &e->sc, err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL fanotifyd: %s\n", err);
		goto fail;
	}
	if (e->sc.fanotifyd_pid > 0)
		rb.fanotify = 1;
	job->state = JOB_MONITOR_READY;
	agd_buf_adds(out, "  ok\n");

	agd_buf_adds(out, "step5 memfdbus...\n");
	if (job_memfdbus_start(job, &e->sc, err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL memfdbus: %s\n", err);
		goto fail;
	}
	if (e->sc.memfdbus_pid > 0)
		rb.memfdbus = 1;
	agd_buf_adds(out, "  ok\n");

	agd_buf_adds(out, "step6 iouringd...\n");
	if (job_iouringd_start(job, &e->sc, e->seq, err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL iouringd: %s\n", err);
		goto fail;
	}
	if (e->sc.iouringd_pid > 0)
		rb.iouringd = 1;
	agd_buf_adds(out, "  ok\n");

	agd_buf_adds(out, "step7 network broker...\n");
	if (job_netd_start(job, &e->sc, err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL network: %s\n", err);
		goto fail;
	}
	if (e->sc.netd_pid > 0)
		rb.netd = 1;
	job->state = JOB_SERVICES_READY;
	agd_buf_addf(out, "  %s\n", err);

	const char *job_init = jobd_component_path(JOBD_COMP_JOB_INIT);
	const char *sandbox    = jobd_component_path(JOBD_COMP_SANDBOX);
	if (!job_init || !sandbox) {
		snprintf(err, sizeof(err), "job-init or sandbox went missing");
		agd_buf_addf(out, "FAIL launch: %s\n", err);
		goto fail;
	}

	char *workload[JOBD_MAX_ARGV + 1];
	if (job_argv(job, workload, JOBD_MAX_ARGV + 1) < 0) {
		snprintf(err, sizeof(err), "cannot materialise argv");
		agd_buf_addf(out, "FAIL launch: %s\n", err);
		goto fail;
	}

	char relay_port[16];
	snprintf(relay_port, sizeof(relay_port), "%d", JOBD_BROKER_PORT);

	char *cav[JOBD_MAX_ARGV + 40];
	int cac = 0;
	cav[cac++] = (char *)job_init;
	cav[cac++] = (char *)"--root";
	cav[cac++] = job->root_path;
	cav[cac++] = (char *)"--network";
	cav[cac++] = (char *)(job->network_mode == JOBD_NETWORK_BROKERED
	                      ? "brokered" : "none");
	cav[cac++] = (char *)"--";

	cav[cac++] = (char *)sandbox;
	cav[cac++] = job->root_path;

	if (job->network_mode == JOBD_NETWORK_BROKERED) {
		cav[cac++] = (char *)"/usr/bin/job-netd";
		cav[cac++] = (char *)"relay";
		cav[cac++] = (char *)"--socket";
		cav[cac++] = (char *)"/run/jobd/net.sock";
		cav[cac++] = (char *)"--port";
		cav[cac++] = relay_port;
		cav[cac++] = (char *)"--";
	}

	cav[cac++] = (char *)"/usr/bin/landlockd";
	cav[cac++] = (char *)"--existing-rootfs";
	cav[cac++] = (char *)"run";
	cav[cac++] = (char *)"--policy-file";
	cav[cac++] = (char *)"/run/jobd/landlock.toml";
	cav[cac++] = (char *)"--";
	for (int i = 0; workload[i]; i++)
		cav[cac++] = workload[i];
	cav[cac] = NULL;

	char  env_buf[ENV_BUF_BYTES];
	char *env_v[MAX_ENV_SLOTS];
	if (job_build_launch_env(job, env_buf, sizeof(env_buf),
	                           env_v, MAX_ENV_SLOTS, err, sizeof(err)) < 0) {
		agd_buf_addf(out, "FAIL environment: %s\n", err);
		goto fail;
	}

	agd_buf_adds(out, "step8 cgroup launch...\n");
	job->state = JOB_LAUNCHING;

	pid_t workload_pid = 0;
	if (job_cgroup_launch(job, cav, env_v, &workload_pid,
	                        err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL launch: %s\n", err);
		goto fail;
	}

	e->workload_pid = workload_pid;
	job->init_pid   = workload_pid;
	clock_gettime(CLOCK_MONOTONIC, &job->start_time);

	if (jobd_job_subdir(job->id, "logs/cgroup.result",
	                      e->result_path, sizeof(e->result_path)) != 0) {
		snprintf(err, sizeof(err), "result path too long");
		agd_buf_addf(out, "FAIL launch: %s\n", err);
		goto fail;
	}

	pid_t waiter = 0;
	if (job_cgroup_start_waiter(job->id, e->result_path, &waiter,
	                              err, sizeof(err)) != 0) {
		agd_buf_addf(out, "FAIL launch: cannot watch the job: %s\n", err);
		job_cgroup_kill(job->id, err, sizeof(err));
		goto fail;
	}

	e->child_pid = waiter;

	e->pidfd = sys_pidfd_open(waiter);
	if (e->pidfd < 0)
		jobd_log("warning: pidfd_open failed for job %s: %s; "
		           "falling back to periodic reaping", job->id,
		           strerror(errno));

	if (job->timeout_ms > 0) {
		e->timer_fd = timerfd_create(CLOCK_MONOTONIC,
		                             TFD_CLOEXEC | TFD_NONBLOCK);
		if (e->timer_fd >= 0) {
			struct itimerspec its;
			memset(&its, 0, sizeof(its));
			its.it_value.tv_sec  = (time_t)(job->timeout_ms / 1000);
			its.it_value.tv_nsec =
				(long)(job->timeout_ms % 1000) * 1000000L;
			if (timerfd_settime(e->timer_fd, 0, &its, NULL) != 0) {
				close(e->timer_fd);
				e->timer_fd = -1;
			}
		}
		if (e->timer_fd < 0)
			jobd_log("warning: no timeout enforcement for job %s: %s",
			           job->id, strerror(errno));
	}

	job->state = JOB_RUNNING;
	agd_buf_addf(out, "  launched workload pid=%d\n", (int)workload_pid);
	agd_buf_addf(out, "\nstate: RUNNING\nlogs: %s\n", job->log_dir);
	agd_buf_addf(out, "use `jobctl wait %s` to await completion\n", job->id);

	jobd_log_event(job->id, "jobd", "launched", display);
	return 0;

fail:
	rollback_unwind(e, &rb);
	job->state = JOB_FAILED;
	job->exit_reason = JOB_EXIT_SETUP;
	jobd_log_event(job->id, "jobd", "setup_failed", err);
	return -1;
}
