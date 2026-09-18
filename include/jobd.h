#ifndef JOBD_JOBD_H
#define JOBD_JOBD_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#include "jobd_buf.h"
#include "jobd_config.h"
#include "protocol.h"
#include "job.h"

#define JOBD_SPAWN_BUF 16384

struct job_spawn_out {
	int   exit_code;
	int   exit_signal;
	int   timed_out;
	char  stdout_buf[JOBD_SPAWN_BUF];
	char  stderr_buf[JOBD_SPAWN_BUF];
	char  errmsg[512];
};

struct job_sidecars {
	pid_t fanotifyd_pid;
	pid_t memfdbus_pid;
	pid_t iouringd_pid;
	char  fanotify_log[JOBD_PATH_LEN_LONG];
	char  fanotify_pidfile[JOBD_PATH_LEN_LONG];
	char  memfdbus_sock[JOBD_PATH_LEN_LONG];
	char  iouringd_sock[JOBD_PATH_LEN_LONG];
	pid_t netd_pid;
	char  netd_sock[JOBD_PATH_LEN_LONG];
};

struct jobd_runtime {
	int foreground;
	int debug;
};

enum job_react_action {
	JOB_REACT_OBSERVE = 0,
	JOB_REACT_DENY    = 1,
	JOB_REACT_FREEZE  = 2,
	JOB_REACT_KILL    = 3,
};

int jobd_recv_msg(int fd, struct jobd_msg_header *hdr,
                    uint8_t *buf, size_t buf_sz, size_t *received);
int jobd_send_msg(int fd, const struct jobd_msg_header *hdr,
                    const uint8_t *payload);
int jobd_send_response(int fd, uint64_t request_id, int status,
                         const uint8_t *data, uint32_t data_len);
int jobd_parse_response(const uint8_t *buf, size_t len,
                          struct jobd_response *resp, const uint8_t **data);
int jobd_read_full(int fd, void *buf, size_t sz);
int jobd_write_full(int fd, const void *buf, size_t sz);

int jobd_encode_run_request(const struct job *job,
                              uint8_t *buf, size_t buf_sz, size_t *out_len,
                              char *err, size_t err_sz);
int jobd_decode_run_request(const uint8_t *buf, size_t len,
                              struct job *job,
                              char *err, size_t err_sz);

int jobd_run_daemon(const struct jobd_runtime *rt);

void jobd_log(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void jobd_log_event(const char *job_id, const char *component,
                      const char *event, const char *extra);
void jobd_log_set_debug(int on);

int jobd_doctor(char *output, size_t output_sz);

int job_kernel_landlock_abi(void);
int job_kernel_seccomp_available(void);
int jobd_policy_plan_dryrun(const struct job *job,
                              char *output, size_t output_sz);

int job_spawn(char *const av[], char *const env[], const char *wd,
                int timeout_ms, struct job_spawn_out *out);
int job_spawn_simple(int timeout_ms, const char *path, ...);

void job_close_fds_above(int keep_max);

#define JOB_ELF_MAX_DEPS 256

struct job_elf_deps {
	char paths[JOB_ELF_MAX_DEPS][JOBD_PATH_LEN_LONG];
	int  count;
	char interp[JOBD_PATH_LEN_LONG];
};

int job_elf_resolve_deps(const char *binary, struct job_elf_deps *out,
                           char *err, size_t err_sz);

int  job_overlay_ensure_store(char *errmsg, size_t errmsg_sz);
int  job_overlay_layer_exists(const char *name);
int  job_overlay_create_ws(const struct job *job,
                             char *errmsg, size_t errmsg_sz);
void job_overlay_remove_ws(const char *job_id);

int job_rootfs_prepare(struct job *job, char *errmsg, size_t errmsg_sz);
int job_landlock_generate_policy(const struct job *job,
                                   const char *policy_path,
                                   char *errmsg, size_t errmsg_sz);

const char *const *job_seccomp_deny_list(void);

int job_cgroup_ensure_daemon(char *errmsg, size_t errmsg_sz);

int job_cgroup_launch(const struct job *job, char *const child_av[],
                        char *const child_env[], pid_t *pid_out,
                        char *errmsg, size_t errmsg_sz);

int job_cgroup_start_waiter(const char *jid, const char *result_path,
                              pid_t *pid_out, char *errmsg, size_t errmsg_sz);

int job_cgroup_read_result(const char *result_path, uint32_t *exit_code,
                             uint32_t *exit_signal, int *oom_killed);
int job_cgroup_kill(const char *jid, char *errmsg, size_t errmsg_sz);
int job_cgroup_freeze(const char *jid, char *errmsg, size_t errmsg_sz);
int job_cgroup_remove(const char *jid, char *errmsg, size_t errmsg_sz);

/* Returns argc (excluding NULL), or -1. Storage is owned by the caller. */
int job_fanotify_build_argv(const struct job *job, const char *bin,
                            const struct job_sidecars *sc, char *argv[],
                            int argv_max,
                            char canary_buf[][JOBD_PATH_LEN_LONG],
                            char *err, size_t err_sz);

/* Failure leaves fanotifyd_pid zero and any spawned child reaped. */
int job_fanotify_start(const struct job *job, struct job_sidecars *sc,
                         char *errmsg, size_t errmsg_sz);
int job_fanotify_stop(struct job_sidecars *sc, char *errmsg, size_t errmsg_sz);

int job_memfdbus_start(const struct job *job, struct job_sidecars *sc,
                         char *errmsg, size_t errmsg_sz);
int job_memfdbus_stop(struct job_sidecars *sc, char *errmsg, size_t errmsg_sz);

#define JOBD_IOURING_RING_ENTRIES  "64"
#define JOBD_IOURING_MAX_CLIENTS   "4"
#define JOBD_IOURING_CREDITS       "64"
#define JOBD_IOURING_IO_BYTES_MAX  "4096"

int job_iouringd_start(const struct job *job, struct job_sidecars *sc,
                         uint32_t seq, char *errmsg, size_t errmsg_sz);
int job_iouringd_stop(struct job_sidecars *sc, char *errmsg, size_t errmsg_sz);

int job_netd_start(const struct job *job, struct job_sidecars *sc,
                     char *errmsg, size_t errmsg_sz);
int job_netd_stop(struct job_sidecars *sc, char *errmsg, size_t errmsg_sz);

int job_sandbox_check_caps(char *errmsg, size_t errmsg_sz);
void job_inotify_set_ready(int ready);
int job_preflight(const struct job *job, char *errmsg, size_t errmsg_sz);

struct job_entry;

int  job_launch(struct job_entry *e, struct agd_buf *out);

void job_reaped(struct job_entry *e, int wstatus);
void job_stop_services(struct job_entry *e);
void job_cleanup_job(struct job_entry *e);
int  job_react(struct job_entry *e, enum job_react_action action,
                 char *errmsg, size_t errmsg_sz);

int  job_monitor_start(struct job_entry *e);
int  job_monitor_fail(struct job_entry *e, const char *cause);
/* 0: no reaction, 1: contained, -1: monitoring or containment failure. */
int  job_monitor_scan_alerts(struct job_entry *e);

int  job_build_launch_env(const struct job *job,
                            char *buf, size_t buf_sz,
                            char **out, int out_max,
                            char *err, size_t err_sz);

#endif
