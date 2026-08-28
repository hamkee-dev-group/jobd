#ifndef JOBD_JOB_H
#define JOBD_JOB_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>

#include "protocol.h"

enum job_state {
	JOB_NEW = 0,
	JOB_VALIDATED,
	JOB_ROOTFS_READY,
	JOB_MONITOR_READY,
	JOB_SERVICES_READY,
	JOB_CGROUP_READY,
	JOB_LAUNCHING,
	JOB_RUNNING,
	JOB_EXITED,
	JOB_KILLED,
	JOB_FAILED,
	JOB_CLEANING,
	JOB_CLEANED
};

enum job_exit_reason {
	JOB_EXIT_NORMAL    = 0,
	JOB_EXIT_SIGNAL    = 1,
	JOB_EXIT_TIMEOUT   = 2,
	JOB_EXIT_OOM       = 3,
	JOB_EXIT_POLICY    = 4,
	JOB_EXIT_SETUP     = 5,
	JOB_EXIT_INTERNAL  = 6,
};

struct job {
	char       id[JOBD_MAX_JOB_ID + 1];
	enum job_state state;

	char       layers[JOBD_MAX_LAYERS][JOBD_MAX_PATH_LEN];
	uint32_t   layer_count;

	char       ro_paths[JOBD_MAX_PATH_COUNT][JOBD_MAX_PATH_LEN];
	uint32_t   ro_count;

	char       rw_paths[JOBD_MAX_PATH_COUNT][JOBD_MAX_PATH_LEN];
	uint32_t   rw_count;

	char       canaries[JOBD_MAX_CANARIES][JOBD_MAX_PATH_LEN];
	uint32_t   canary_count;

	struct {
		char   name[JOBD_MAX_PATH_LEN];
		char   path[JOBD_MAX_PATH_LEN];
	} memfd_inputs[JOBD_MAX_MEMFD_INPUT];
	uint32_t   memfd_input_count;

	uint64_t   memory_max;
	uint64_t   memory_high;
	uint64_t   swap_max;
	uint64_t   cpu_max_q;
	uint64_t   cpu_max_p;
	uint32_t   cpu_weight;
	uint32_t   pids_max;
	uint32_t   io_weight;
	uint64_t   timeout_ms;

	char       allow_net[JOBD_MAX_ALLOW_NET][JOBD_MAX_ALLOW_LEN];
	uint32_t   allow_net_count;

	uint8_t    network_mode;
	uint8_t    fanotify_mode;
	uint8_t    iouring_enabled;
	uint8_t    dry_run;

	char       root_path[JOBD_PATH_LEN_LONG];
	char       export_path[JOBD_PATH_LEN_LONG];
	char       policy_path[JOBD_PATH_LEN_LONG];
	char       log_dir[JOBD_PATH_LEN_LONG];

	char       argv_buf[JOBD_ARGV_BYTES];
	size_t     argv_bytes;
	uint32_t   argc;

	char       env_buf[JOBD_ENV_BYTES];
	size_t     env_bytes;
	uint32_t   envc;

	struct timespec start_time;
	struct timespec end_time;

	pid_t      init_pid;
	uint32_t   exit_code;
	uint32_t   exit_signal;
	enum job_exit_reason exit_reason;
};

const char *job_state_name(enum job_state s);
const char *job_exit_reason_name(enum job_exit_reason r);
int  job_state_is_terminal(enum job_state s);

int  job_id_validate(const char *id, char *err, size_t err_sz);

int  job_allow_net_validate(const char *entry, char *err, size_t err_sz);
int  job_validate(const struct job *job, char *err, size_t err_sz);
int  job_features_check(const struct job *job, char *err, size_t err_sz);
void job_set_defaults(struct job *job);

int  job_add_arg(struct job *job, const char *arg,
                       char *err, size_t err_sz);
int  job_add_env(struct job *job, const char *kv,
                       char *err, size_t err_sz);

int  job_argv(const struct job *job, char **out, int out_max);
int  job_env(const struct job *job, char **out, int out_max);

void job_argv_display(const struct job *job,
                            char *out, size_t out_sz);

#endif
