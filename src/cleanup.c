#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "jobd.h"
#include "state.h"

static void rmtree_at(int parent_fd, const char *name, int depth)
{
	if (depth > 64)
		return;

	int fd = openat(parent_fd, name,
	                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		unlinkat(parent_fd, name, 0);
		return;
	}

	DIR *d = fdopendir(fd);
	if (!d) {
		close(fd);
		unlinkat(parent_fd, name, AT_REMOVEDIR);
		return;
	}

	struct dirent *ent;
	while ((ent = readdir(d))) {
		if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
			continue;

		int is_dir = 0;
		if (ent->d_type == DT_DIR) {
			is_dir = 1;
		} else if (ent->d_type == DT_UNKNOWN) {
			struct stat st;
			if (fstatat(dirfd(d), ent->d_name, &st,
			            AT_SYMLINK_NOFOLLOW) == 0)
				is_dir = S_ISDIR(st.st_mode);
		}

		if (is_dir)
			rmtree_at(dirfd(d), ent->d_name, depth + 1);
		else
			unlinkat(dirfd(d), ent->d_name, 0);
	}

	closedir(d);
	unlinkat(parent_fd, name, AT_REMOVEDIR);
}

static void rmtree(const char *path)
{
	char tmp[JOBD_PATH_LEN_LONG];
	int n = snprintf(tmp, sizeof(tmp), "%s", path);
	if (n < 0 || (size_t)n >= sizeof(tmp))
		return;

	char *slash = strrchr(tmp, '/');
	if (!slash || slash == tmp) {

		return;
	}
	*slash = '\0';
	const char *base = slash + 1;
	if (!*base || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
		return;

	int parent = open(tmp, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (parent < 0)
		return;
	rmtree_at(parent, base, 0);
	close(parent);
}

void job_stop_services(struct job_entry *e)
{
	char err[256];

	job_netd_stop(&e->sc, err, sizeof(err));
	job_iouringd_stop(&e->sc, err, sizeof(err));
	job_memfdbus_stop(&e->sc, err, sizeof(err));
	job_fanotify_stop(&e->sc, err, sizeof(err));

	job_cgroup_kill(e->job.id, err, sizeof(err));
	job_cgroup_remove(e->job.id, err, sizeof(err));

	if (e->pidfd >= 0) {
		close(e->pidfd);
		e->pidfd = -1;
	}
	if (e->timer_fd >= 0) {
		close(e->timer_fd);
		e->timer_fd = -1;
	}
}

void job_reaped(struct job_entry *e, int wstatus)
{
	struct job *job = &e->job;

	clock_gettime(CLOCK_MONOTONIC, &job->end_time);

	uint32_t code = 0, sig = 0;
	int oom = 0;

	if (e->result_path[0] &&
	    job_cgroup_read_result(e->result_path, &code, &sig, &oom) == 0) {
		job->exit_code   = code;
		job->exit_signal = sig;
		if (oom)
			job->exit_reason = JOB_EXIT_OOM;
		else if (sig != 0 && job->exit_reason == JOB_EXIT_NORMAL)
			job->exit_reason = JOB_EXIT_SIGNAL;
	} else if (WIFEXITED(wstatus)) {
		job->exit_code = (uint32_t)WEXITSTATUS(wstatus);
	} else if (WIFSIGNALED(wstatus)) {
		job->exit_signal = (uint32_t)WTERMSIG(wstatus);
		if (job->exit_reason == JOB_EXIT_NORMAL)
			job->exit_reason = JOB_EXIT_SIGNAL;
	}

	if (job->exit_signal != 0 && job->exit_reason == JOB_EXIT_NORMAL)
		job->exit_reason = JOB_EXIT_SIGNAL;

	if (job->exit_reason == JOB_EXIT_SIGNAL ||
	    job->exit_reason == JOB_EXIT_OOM)
		job->state = JOB_KILLED;

	if (job->exit_reason == JOB_EXIT_TIMEOUT ||
	    job->exit_reason == JOB_EXIT_POLICY)
		job->state = JOB_KILLED;
	else if (!job_state_is_terminal(job->state))
		job->state = JOB_EXITED;

	e->child_pid = 0;

	job_stop_services(e);

	char err[256];
	job_state_save(job, err, sizeof(err));

	char extra[128];
	snprintf(extra, sizeof(extra), "exit_code=%u signal=%u reason=%s",
	         job->exit_code, job->exit_signal,
	         job_exit_reason_name(job->exit_reason));
	jobd_log_event(job->id, "jobd", "finished", extra);
	jobd_log("job %s finished: %s", job->id, extra);
}

void job_cleanup_job(struct job_entry *e)
{
	jobd_log("cleanup: job %s", e->job.id);
	e->job.state = JOB_CLEANING;

	job_stop_services(e);

	job_overlay_remove_ws(e->job.id);

	if (e->job.root_path[0]) {
		umount2(e->job.root_path, MNT_DETACH);
		rmtree(e->job.root_path);
	}

	char dir[JOBD_PATH_LEN_LONG];
	if (jobd_job_dir(e->job.id, dir, sizeof(dir)) == 0)
		rmtree(dir);

	e->job.state = JOB_CLEANED;
	jobd_log("cleanup: %s done", e->job.id);
}
