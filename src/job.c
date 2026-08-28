#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "jobd_buf.h"
#include "jobd_config.h"
#include "job.h"

const char *job_state_name(enum job_state s)
{
	switch (s) {
	case JOB_NEW:            return "NEW";
	case JOB_VALIDATED:      return "VALIDATED";
	case JOB_ROOTFS_READY:   return "ROOTFS_READY";
	case JOB_MONITOR_READY:  return "MONITOR_READY";
	case JOB_SERVICES_READY: return "SERVICES_READY";
	case JOB_CGROUP_READY:   return "CGROUP_READY";
	case JOB_LAUNCHING:      return "LAUNCHING";
	case JOB_RUNNING:        return "RUNNING";
	case JOB_EXITED:         return "EXITED";
	case JOB_KILLED:         return "KILLED";
	case JOB_FAILED:         return "FAILED";
	case JOB_CLEANING:       return "CLEANING";
	case JOB_CLEANED:        return "CLEANED";
	default: return "UNKNOWN";
	}
}

const char *job_exit_reason_name(enum job_exit_reason r)
{
	switch (r) {
	case JOB_EXIT_NORMAL:   return "EXITED";
	case JOB_EXIT_SIGNAL:   return "SIGNALED";
	case JOB_EXIT_TIMEOUT:  return "TIMEOUT";
	case JOB_EXIT_OOM:      return "OOM";
	case JOB_EXIT_POLICY:   return "POLICY_KILL";
	case JOB_EXIT_SETUP:    return "SETUP_FAILURE";
	case JOB_EXIT_INTERNAL: return "INTERNAL";
	default: return "UNKNOWN";
	}
}

int job_state_is_terminal(enum job_state s)
{
	switch (s) {
	case JOB_EXITED:
	case JOB_KILLED:
	case JOB_FAILED:
	case JOB_CLEANED:
		return 1;
	default:
		return 0;
	}
}

int job_id_validate(const char *id, char *err, size_t err_sz)
{
	if (!id) {
		snprintf(err, err_sz, "job ID is NULL");
		return -1;
	}

	size_t len = strlen(id);
	if (len == 0) {
		snprintf(err, err_sz, "job ID is empty");
		return -1;
	}
	if (len > JOBD_MAX_JOB_ID) {
		snprintf(err, err_sz, "job ID too long (%zu > %u)",
		         len, JOBD_MAX_JOB_ID);
		return -1;
	}

	for (size_t i = 0; i < len; i++) {
		char c = id[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') || c == '_' || c == '-')
			continue;
		snprintf(err, err_sz, "invalid job ID character: '%c' (0x%02x)",
		         c, (unsigned char)c);
		return -1;
	}

	return 0;
}

static int validate_client_path(const char *p, const char *what,
                                char *err, size_t err_sz)
{
	if (p[0] != '/') {
		snprintf(err, err_sz, "%s must be an absolute path: %s", what, p);
		return -1;
	}

	for (const unsigned char *c = (const unsigned char *)p; *c; c++) {
		if (*c < 0x20 || *c == 0x7f) {
			snprintf(err, err_sz,
			         "%s contains a control character", what);
			return -1;
		}
	}

	if (strstr(p, "/../") || strstr(p, "//")) {
		snprintf(err, err_sz, "%s contains '..' or empty component: %s",
		         what, p);
		return -1;
	}

	size_t len = strlen(p);
	if (len >= 3 && strcmp(p + len - 3, "/..") == 0) {
		snprintf(err, err_sz, "%s ends with '..': %s", what, p);
		return -1;
	}

	return 0;
}

int job_allow_net_validate(const char *entry, char *err, size_t err_sz)
{
	if (!entry || !*entry) {
		snprintf(err, err_sz, "--allow-net entry is empty");
		return -1;
	}

	const char *colon = strrchr(entry, ':');
	if (!colon || colon == entry) {
		snprintf(err, err_sz,
		         "--allow-net expects HOST:PORT, got '%s'", entry);
		return -1;
	}

	size_t hlen = (size_t)(colon - entry);
	if (hlen >= JOBD_MAX_ALLOW_LEN - 8) {
		snprintf(err, err_sz, "--allow-net host is too long");
		return -1;
	}

	for (size_t i = 0; i < hlen; i++) {
		char c = entry[i];
		if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') ||
		    c == '.' || c == '-' || c == '_' || c == ':')
			continue;
		snprintf(err, err_sz,
		         "--allow-net host contains an invalid character: '%c'", c);
		return -1;
	}

	if (colon[1] == '\0') {
		snprintf(err, err_sz, "--allow-net is missing a port: '%s'", entry);
		return -1;
	}

	unsigned long port = 0;
	for (const char *p = colon + 1; *p; p++) {
		if (*p < '0' || *p > '9') {
			snprintf(err, err_sz,
			         "--allow-net port is not a number: '%s'", entry);
			return -1;
		}
		port = port * 10 + (unsigned long)(*p - '0');
		if (port > 65535)
			break;
	}
	if (port == 0 || port > 65535) {
		snprintf(err, err_sz,
		         "--allow-net port must be 1..65535: '%s'", entry);
		return -1;
	}

	return 0;
}

int job_features_check(const struct job *job, char *err, size_t err_sz)
{
	const struct jobd_features *f = jobd_features();

	if (!job) {
		snprintf(err, err_sz, "job is NULL");
		return -1;
	}

	if (job->iouring_enabled && !f->allow_iouring) {
		snprintf(err, err_sz,
		         "io_uring is disabled by the daemon (allow_iouring)");
		return -1;
	}
	if (job->network_mode != JOBD_NETWORK_NONE && !f->allow_network) {
		snprintf(err, err_sz,
		         "networking is disabled by the daemon (allow_network)");
		return -1;
	}
	if (job->fanotify_mode != JOBD_FANOTIFY_OFF && !f->allow_fanotify) {
		snprintf(err, err_sz,
		         "fanotify is disabled by the daemon (allow_fanotify)");
		return -1;
	}
	if (job->memfd_input_count > 0 && !f->allow_memfd) {
		snprintf(err, err_sz,
		         "memfd inputs are disabled by the daemon (allow_memfd)");
		return -1;
	}

	return 0;
}

int job_validate(const struct job *job, char *err, size_t err_sz)
{
	if (!job) {
		snprintf(err, err_sz, "job is NULL");
		return -1;
	}

	if (job_id_validate(job->id, err, err_sz) != 0)
		return -1;

	if (job->argc == 0 || job->argv_buf[0] == '\0') {
		snprintf(err, err_sz, "command (argv) is empty");
		return -1;
	}
	if (job->argc > JOBD_MAX_ARGV) {
		snprintf(err, err_sz, "too many arguments (%u > %u)",
		         job->argc, JOBD_MAX_ARGV);
		return -1;
	}
	if (job->argv_buf[0] != '/') {
		snprintf(err, err_sz,
		         "command must be an absolute path: %s", job->argv_buf);
		return -1;
	}

	if (job->envc > JOBD_MAX_ENV_COUNT) {
		snprintf(err, err_sz, "too many environment entries (%u > %u)",
		         job->envc, JOBD_MAX_ENV_COUNT);
		return -1;
	}

	if (job->layer_count > JOBD_MAX_LAYERS) {
		snprintf(err, err_sz, "too many layers (%u > %u)",
		         job->layer_count, JOBD_MAX_LAYERS);
		return -1;
	}
	if (job->ro_count > JOBD_MAX_PATH_COUNT) {
		snprintf(err, err_sz, "too many --ro paths (%u > %u)",
		         job->ro_count, JOBD_MAX_PATH_COUNT);
		return -1;
	}
	if (job->rw_count > JOBD_MAX_PATH_COUNT) {
		snprintf(err, err_sz, "too many --rw paths (%u > %u)",
		         job->rw_count, JOBD_MAX_PATH_COUNT);
		return -1;
	}
	if (job->canary_count > JOBD_MAX_CANARIES) {
		snprintf(err, err_sz, "too many canary paths (%u > %u)",
		         job->canary_count, JOBD_MAX_CANARIES);
		return -1;
	}
	if (job->memfd_input_count > JOBD_MAX_MEMFD_INPUT) {
		snprintf(err, err_sz, "too many memfd inputs (%u > %u)",
		         job->memfd_input_count, JOBD_MAX_MEMFD_INPUT);
		return -1;
	}

	for (uint32_t i = 0; i < job->ro_count; i++) {
		if (validate_client_path(job->ro_paths[i], "--ro", err, err_sz) != 0)
			return -1;
	}
	for (uint32_t i = 0; i < job->rw_count; i++) {
		if (validate_client_path(job->rw_paths[i], "--rw", err, err_sz) != 0)
			return -1;
	}
	for (uint32_t i = 0; i < job->canary_count; i++) {
		if (validate_client_path(job->canaries[i], "--canary",
		                         err, err_sz) != 0)
			return -1;
	}
	for (uint32_t i = 0; i < job->memfd_input_count; i++) {
		if (validate_client_path(job->memfd_inputs[i].path,
		                         "--memfd-input path", err, err_sz) != 0)
			return -1;
		if (job->memfd_inputs[i].name[0] == '\0') {
			snprintf(err, err_sz, "--memfd-input name is empty");
			return -1;
		}
	}
	for (uint32_t i = 0; i < job->layer_count; i++) {
		if (job->layers[i][0] == '\0') {
			snprintf(err, err_sz, "--layer name is empty");
			return -1;
		}
		if (strchr(job->layers[i], '/')) {
			snprintf(err, err_sz,
			         "--layer must be a name, not a path: %s",
			         job->layers[i]);
			return -1;
		}
	}

	if (job->pids_max == 0) {
		snprintf(err, err_sz, "pids_max must be > 0");
		return -1;
	}

	if (job->network_mode != JOBD_NETWORK_NONE &&
	    job->network_mode != JOBD_NETWORK_BROKERED) {
		snprintf(err, err_sz, "unsupported network mode: %u",
		         job->network_mode);
		return -1;
	}

	if (job->allow_net_count > JOBD_MAX_ALLOW_NET) {
		snprintf(err, err_sz, "too many --allow-net entries (%u > %u)",
		         job->allow_net_count, JOBD_MAX_ALLOW_NET);
		return -1;
	}

	if (job->network_mode == JOBD_NETWORK_NONE &&
	    job->allow_net_count > 0) {
		snprintf(err, err_sz,
		         "--allow-net requires --network brokered");
		return -1;
	}
	if (job->network_mode == JOBD_NETWORK_BROKERED &&
	    job->allow_net_count == 0) {
		snprintf(err, err_sz,
		         "--network brokered requires at least one --allow-net "
		         "HOST:PORT");
		return -1;
	}

	for (uint32_t i = 0; i < job->allow_net_count; i++) {
		if (job_allow_net_validate(job->allow_net[i], err, err_sz) != 0)
			return -1;
	}

	if (job->fanotify_mode > JOBD_FANOTIFY_DENY) {
		snprintf(err, err_sz, "invalid fanotify mode: %u",
		         job->fanotify_mode);
		return -1;
	}

	return 0;
}

void job_set_defaults(struct job *job)
{
	memset(job, 0, sizeof(*job));
	job->pids_max   = 128;
	job->swap_max   = 0;
	job->cpu_max_q  = 100000;
	job->cpu_max_p  = 100000;
	job->cpu_weight = 100;
	job->io_weight  = 100;
	job->timeout_ms = 300000;
}

static int add_element(char *buf, size_t buf_sz, size_t *used, uint32_t *count,
                       uint32_t max_count, size_t max_len,
                       const char *what, const char *s,
                       char *err, size_t err_sz)
{
	if (*count >= max_count) {
		snprintf(err, err_sz, "too many %s entries (max %u)",
		         what, max_count);
		return -1;
	}

	size_t len = strlen(s);
	if (len >= max_len) {
		snprintf(err, err_sz, "%s entry too long (%zu >= %zu)",
		         what, len, max_len);
		return -1;
	}
	if (len + 1 > buf_sz - *used) {
		snprintf(err, err_sz, "%s storage exhausted", what);
		return -1;
	}

	memcpy(buf + *used, s, len + 1);
	*used += len + 1;
	(*count)++;
	return 0;
}

int job_add_arg(struct job *job, const char *arg,
                      char *err, size_t err_sz)
{
	return add_element(job->argv_buf, sizeof(job->argv_buf),
	                   &job->argv_bytes, &job->argc,
	                   JOBD_MAX_ARGV, JOBD_MAX_ARG_LEN,
	                   "argv", arg, err, err_sz);
}

int job_add_env(struct job *job, const char *kv,
                      char *err, size_t err_sz)
{
	if (!strchr(kv, '=')) {
		snprintf(err, err_sz, "environment entry must be KEY=VALUE: %s", kv);
		return -1;
	}
	if (kv[0] == '=') {
		snprintf(err, err_sz, "environment entry has an empty key");
		return -1;
	}
	return add_element(job->env_buf, sizeof(job->env_buf),
	                   &job->env_bytes, &job->envc,
	                   JOBD_MAX_ENV_COUNT, JOBD_MAX_ENV_LEN,
	                   "env", kv, err, err_sz);
}

static int build_vector(const char *buf, size_t used, uint32_t count,
                        char **out, int out_max)
{
	if (out_max <= 0 || (uint32_t)(out_max - 1) < count)
		return -1;

	size_t off = 0;
	uint32_t n = 0;
	while (n < count && off < used) {
		out[n++] = (char *)(buf + off);
		off += strlen(buf + off) + 1;
	}
	out[n] = NULL;
	return (n == count) ? (int)n : -1;
}

int job_argv(const struct job *job, char **out, int out_max)
{
	return build_vector(job->argv_buf, job->argv_bytes, job->argc,
	                    out, out_max);
}

int job_env(const struct job *job, char **out, int out_max)
{
	return build_vector(job->env_buf, job->env_bytes, job->envc,
	                    out, out_max);
}

void job_argv_display(const struct job *job,
                            char *out, size_t out_sz)
{
	struct agd_buf b;
	agd_buf_init(&b, out, out_sz);

	size_t off = 0;
	for (uint32_t i = 0; i < job->argc && off < job->argv_bytes; i++) {
		const char *arg = job->argv_buf + off;
		if (i > 0)
			agd_buf_addch(&b, ' ');
		agd_buf_adds(&b, arg);
		off += strlen(arg) + 1;
	}
}
