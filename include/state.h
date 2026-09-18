#ifndef JOBD_STATE_H
#define JOBD_STATE_H

#include <stdint.h>
#include <sys/types.h>

#include "jobd.h"
#include "job.h"

#define MAX_JOBS         256
#define MAX_JOB_WAITERS  16

struct job_waiter {
	int      fd;
	uint64_t request_id;
};

struct job_entry {
	struct job      job;
	struct job_sidecars sc;

	uint32_t seq;

	pid_t    workload_pid;
	pid_t    child_pid;
	char     result_path[JOBD_PATH_LEN_LONG];
	int      pidfd;
	int      timer_fd;
	int      log_wd;
	long     log_off;
	dev_t    log_dev;
	ino_t    log_ino;
	int      log_identity_set;
	int      monitor_failed;
	int      containment_pending;
	int      reacted;
	int      waiter_exited;
	int      waiter_status;

	struct job_waiter waiters[MAX_JOB_WAITERS];
	int      waiter_count;

	struct job_entry *next;
};

void job_table_init(void);
struct job_entry *job_table_add(const struct job *job);
struct job_entry *job_table_find(const char *id);
void job_table_remove(const char *id);
int  job_table_size(void);
void job_table_foreach(void (*fn)(struct job_entry *, void *), void *ctx);

int job_state_save(const struct job *job, char *err, size_t err_sz);
int job_state_load(const char *id, struct job *job,
                     char *err, size_t err_sz);
int job_state_delete(const char *id);
int job_recover_stale_jobs(void);

#endif
