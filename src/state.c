#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "jobd.h"
#include "state.h"

static struct job_entry *jtable[MAX_JOBS];
static int job_count;

static unsigned int hash_id(const char *id)
{
	unsigned int h = 5381;
	while (*id)
		h = ((h << 5) + h) + (unsigned char)*id++;
	return h % MAX_JOBS;
}

static void entry_free(struct job_entry *e)
{
	if (e->pidfd >= 0)
		close(e->pidfd);
	if (e->timer_fd >= 0)
		close(e->timer_fd);
	for (int i = 0; i < e->waiter_count; i++) {
		if (e->waiters[i].fd >= 0)
			close(e->waiters[i].fd);
	}
	free(e);
}

void job_table_init(void)
{
	for (int i = 0; i < MAX_JOBS; i++) {
		struct job_entry *next;
		for (struct job_entry *e = jtable[i]; e; e = next) {
			next = e->next;
			entry_free(e);
		}
		jtable[i] = NULL;
	}
	job_count = 0;
}

struct job_entry *job_table_add(const struct job *job)
{
	struct job_entry *e = calloc(1, sizeof(*e));
	if (!e)
		return NULL;

	static uint32_t next_seq = 1;

	memcpy(&e->job, job, sizeof(*job));
	e->seq      = next_seq++;
	e->pidfd    = -1;
	e->timer_fd = -1;
	e->log_wd   = -1;

	unsigned int h = hash_id(job->id);
	e->next   = jtable[h];
	jtable[h] = e;
	job_count++;
	return e;
}

struct job_entry *job_table_find(const char *id)
{
	unsigned int h = hash_id(id);
	for (struct job_entry *e = jtable[h]; e; e = e->next) {
		if (strcmp(e->job.id, id) == 0)
			return e;
	}
	return NULL;
}

void job_table_remove(const char *id)
{
	unsigned int h = hash_id(id);
	struct job_entry **prev = &jtable[h];

	while (*prev) {
		if (strcmp((*prev)->job.id, id) == 0) {
			struct job_entry *d = *prev;
			*prev = d->next;
			entry_free(d);
			job_count--;
			return;
		}
		prev = &(*prev)->next;
	}
}

int job_table_size(void) { return job_count; }

void job_table_foreach(void (*fn)(struct job_entry *, void *), void *ctx)
{
	for (int i = 0; i < MAX_JOBS; i++) {
		struct job_entry *next;
		for (struct job_entry *e = jtable[i]; e; e = next) {
			next = e->next;
			fn(e, ctx);
		}
	}
}

int job_state_save(const struct job *job, char *err, size_t err_sz)
{
	const struct jobd_paths *p = jobd_paths();

	char dir[JOBD_PATH_LEN_LONG];
	if (jobd_job_state_dir(job->id, dir, sizeof(dir)) != 0) {
		snprintf(err, err_sz, "state path too long");
		return -1;
	}

	mkdir(p->state_dir, 0700);
	mkdir(p->jobs_dir, 0700);
	if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
		snprintf(err, err_sz, "cannot create %s: %s", dir, strerror(errno));
		return -1;
	}

	char path[JOBD_PATH_LEN_LONG], tmp[JOBD_PATH_LEN_LONG];
	int n = snprintf(path, sizeof(path), "%s/state.json", dir);
	if (n < 0 || (size_t)n >= sizeof(path)) {
		snprintf(err, err_sz, "state path too long");
		return -1;
	}
	n = snprintf(tmp, sizeof(tmp), "%s/state.json.tmp", dir);
	if (n < 0 || (size_t)n >= sizeof(tmp)) {
		snprintf(err, err_sz, "state path too long");
		return -1;
	}

	char text[8192];
	struct agd_buf b;
	agd_buf_init(&b, text, sizeof(text));

	char display[4096];
	job_argv_display(job, display, sizeof(display));

	agd_buf_adds(&b, "{\"id\":\"");
	agd_buf_add_json(&b, job->id);
	agd_buf_adds(&b, "\",\"state\":\"");
	agd_buf_add_json(&b, job_state_name(job->state));
	agd_buf_adds(&b, "\",\"argv\":\"");
	agd_buf_add_json(&b, display);
	agd_buf_adds(&b, "\",\"exit_reason\":\"");
	agd_buf_add_json(&b, job_exit_reason_name(job->exit_reason));
	agd_buf_addf(&b, "\",\"exit_code\":%u,\"exit_signal\":%u,\"pids_max\":%u}\n",
	             job->exit_code, job->exit_signal, job->pids_max);

	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
	              0600);
	if (fd < 0) {
		snprintf(err, err_sz, "cannot open %s: %s", tmp, strerror(errno));
		return -1;
	}
	if (jobd_write_full(fd, text, agd_buf_len(&b)) != 0 || fsync(fd) != 0) {
		snprintf(err, err_sz, "cannot write %s: %s", tmp, strerror(errno));
		close(fd);
		unlink(tmp);
		return -1;
	}
	close(fd);

	if (rename(tmp, path) != 0) {
		snprintf(err, err_sz, "cannot install %s: %s", path, strerror(errno));
		unlink(tmp);
		return -1;
	}

	snprintf(err, err_sz, "saved");
	return 0;
}

static int json_get_string(const char *text, const char *key,
                           char *out, size_t out_sz)
{
	char pattern[64];
	int n = snprintf(pattern, sizeof(pattern), "\"%s\":\"", key);
	if (n < 0 || (size_t)n >= sizeof(pattern))
		return -1;

	const char *p = strstr(text, pattern);
	if (!p)
		return -1;
	p += n;

	size_t used = 0;
	while (*p && *p != '"') {
		char c = *p++;
		if (c == '\\' && *p) {
			char esc = *p++;
			switch (esc) {
			case 'n':  c = '\n'; break;
			case 't':  c = '\t'; break;
			case 'r':  c = '\r'; break;
			case 'b':  c = '\b'; break;
			case 'f':  c = '\f'; break;
			case '"':  c = '"';  break;
			case '\\': c = '\\'; break;
			case 'u':

				for (int i = 0; i < 4 && *p; i++)
					p++;
				continue;
			default:
				c = esc;
				break;
			}
		}
		if (used + 1 >= out_sz)
			return -1;
		out[used++] = c;
	}

	if (*p != '"')
		return -1;
	out[used] = '\0';
	return 0;
}

static int json_get_uint(const char *text, const char *key, uint32_t *out)
{
	char pattern[64];
	int n = snprintf(pattern, sizeof(pattern), "\"%s\":", key);
	if (n < 0 || (size_t)n >= sizeof(pattern))
		return -1;

	const char *p = strstr(text, pattern);
	if (!p)
		return -1;
	p += n;

	char *end = NULL;
	errno = 0;
	unsigned long v = strtoul(p, &end, 10);
	if (errno != 0 || end == p || v > 0xFFFFFFFFUL)
		return -1;

	*out = (uint32_t)v;
	return 0;
}

static enum job_state state_from_name(const char *name)
{
	for (int i = JOB_NEW; i <= JOB_CLEANED; i++) {
		if (strcmp(job_state_name((enum job_state)i), name) == 0)
			return (enum job_state)i;
	}
	return JOB_NEW;
}

static enum job_exit_reason reason_from_name(const char *name)
{
	for (int i = JOB_EXIT_NORMAL; i <= JOB_EXIT_INTERNAL; i++) {
		if (strcmp(job_exit_reason_name((enum job_exit_reason)i),
		           name) == 0)
			return (enum job_exit_reason)i;
	}
	return JOB_EXIT_NORMAL;
}

int job_state_load(const char *id, struct job *job,
                     char *err, size_t err_sz)
{
	char dir[JOBD_PATH_LEN_LONG], path[JOBD_PATH_LEN_LONG];

	if (job_id_validate(id, err, err_sz) != 0)
		return -1;
	if (jobd_job_state_dir(id, dir, sizeof(dir)) != 0) {
		snprintf(err, err_sz, "state path too long");
		return -1;
	}
	int n = snprintf(path, sizeof(path), "%s/state.json", dir);
	if (n < 0 || (size_t)n >= sizeof(path)) {
		snprintf(err, err_sz, "state path too long");
		return -1;
	}

	int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		snprintf(err, err_sz, "no saved state for %s", id);
		return -1;
	}

	char text[8192];
	ssize_t got = read(fd, text, sizeof(text) - 1);
	close(fd);
	if (got <= 0) {
		snprintf(err, err_sz, "state file for %s is empty", id);
		return -1;
	}
	text[got] = '\0';

	job_set_defaults(job);

	char value[4096];
	if (json_get_string(text, "id", value, sizeof(value)) != 0) {
		snprintf(err, err_sz, "state file for %s has no id", id);
		return -1;
	}
	if (strcmp(value, id) != 0) {
		snprintf(err, err_sz, "state file for %s records a different id",
		         id);
		return -1;
	}

	memcpy(job->id, id, strlen(id) + 1);

	if (json_get_string(text, "state", value, sizeof(value)) == 0)
		job->state = state_from_name(value);
	if (json_get_string(text, "exit_reason", value, sizeof(value)) == 0)
		job->exit_reason = reason_from_name(value);
	if (json_get_string(text, "argv", value, sizeof(value)) == 0) {

		size_t len = strlen(value);
		if (len < sizeof(job->argv_buf)) {
			memcpy(job->argv_buf, value, len + 1);
			job->argv_bytes = len + 1;
			job->argc = len > 0 ? 1 : 0;
		}
	}

	json_get_uint(text, "exit_code", &job->exit_code);
	json_get_uint(text, "exit_signal", &job->exit_signal);
	json_get_uint(text, "pids_max", &job->pids_max);
	if (job->pids_max == 0)
		job->pids_max = 128;

	snprintf(err, err_sz, "loaded");
	return 0;
}

int job_state_delete(const char *id)
{
	char dir[JOBD_PATH_LEN_LONG], path[JOBD_PATH_LEN_LONG];

	if (jobd_job_state_dir(id, dir, sizeof(dir)) != 0)
		return -1;

	int n = snprintf(path, sizeof(path), "%s/state.json", dir);
	if (n > 0 && (size_t)n < sizeof(path))
		unlink(path);
	rmdir(dir);
	return 0;
}

int job_recover_stale_jobs(void)
{
	const char *runtime = jobd_paths()->runtime_dir;

	jobd_log("recovery: scanning %s", runtime);

	DIR *d = opendir(runtime);
	if (!d)
		return 0;

	struct dirent *ent;
	int cleaned = 0;

	while ((ent = readdir(d))) {
		if (ent->d_name[0] == '.')
			continue;

		struct stat st;
		if (fstatat(dirfd(d), ent->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
			continue;
		if (!S_ISDIR(st.st_mode))
			continue;

		char err[256];
		if (job_id_validate(ent->d_name, err, sizeof(err)) != 0)
			continue;

		jobd_log("recovery: reclaiming stale job %s", ent->d_name);

		struct job_entry e;
		memset(&e, 0, sizeof(e));
		e.pidfd    = -1;
		e.timer_fd = -1;
		e.log_wd   = -1;

		memcpy(e.job.id, ent->d_name, strlen(ent->d_name) + 1);
		jobd_job_subdir(ent->d_name, "root", e.job.root_path,
		                  sizeof(e.job.root_path));

		job_cleanup_job(&e);
		job_state_delete(ent->d_name);
		cleaned++;
	}

	closedir(d);
	jobd_log("recovery: reclaimed %d stale job(s)", cleaned);
	return 0;
}
