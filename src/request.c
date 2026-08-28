#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "jobd.h"

int jobd_encode_run_request(const struct job *job,
                              uint8_t *buf, size_t buf_sz, size_t *out_len,
                              char *err, size_t err_sz)
{
	struct agd_wr w;
	agd_wr_init(&w, buf, buf_sz);

	agd_wr_u64(&w, job->memory_max);
	agd_wr_u64(&w, job->memory_high);
	agd_wr_u64(&w, job->swap_max);
	agd_wr_u64(&w, job->cpu_max_q);
	agd_wr_u64(&w, job->cpu_max_p);
	agd_wr_u64(&w, job->timeout_ms);
	agd_wr_u32(&w, job->cpu_weight);
	agd_wr_u32(&w, job->pids_max);
	agd_wr_u32(&w, job->io_weight);
	agd_wr_u8(&w, job->network_mode);
	agd_wr_u8(&w, job->fanotify_mode);
	agd_wr_u8(&w, job->iouring_enabled);
	agd_wr_u8(&w, job->dry_run);

	agd_wr_str(&w, job->id);

	agd_wr_u32(&w, job->layer_count);
	for (uint32_t i = 0; i < job->layer_count; i++)
		agd_wr_str(&w, job->layers[i]);

	agd_wr_u32(&w, job->ro_count);
	for (uint32_t i = 0; i < job->ro_count; i++)
		agd_wr_str(&w, job->ro_paths[i]);

	agd_wr_u32(&w, job->rw_count);
	for (uint32_t i = 0; i < job->rw_count; i++)
		agd_wr_str(&w, job->rw_paths[i]);

	agd_wr_u32(&w, job->canary_count);
	for (uint32_t i = 0; i < job->canary_count; i++)
		agd_wr_str(&w, job->canaries[i]);

	agd_wr_u32(&w, job->memfd_input_count);
	for (uint32_t i = 0; i < job->memfd_input_count; i++) {
		agd_wr_str(&w, job->memfd_inputs[i].name);
		agd_wr_str(&w, job->memfd_inputs[i].path);
	}

	agd_wr_u32(&w, job->allow_net_count);
	for (uint32_t i = 0; i < job->allow_net_count; i++)
		agd_wr_str(&w, job->allow_net[i]);

	agd_wr_u32(&w, job->argc);
	{
		size_t off = 0;
		for (uint32_t i = 0; i < job->argc; i++) {
			const char *a = job->argv_buf + off;
			agd_wr_str(&w, a);
			off += strlen(a) + 1;
		}
	}

	agd_wr_u32(&w, job->envc);
	{
		size_t off = 0;
		for (uint32_t i = 0; i < job->envc; i++) {
			const char *e = job->env_buf + off;
			agd_wr_str(&w, e);
			off += strlen(e) + 1;
		}
	}

	if (!agd_wr_ok(&w)) {
		snprintf(err, err_sz, "request does not fit in %zu bytes", buf_sz);
		return -1;
	}

	*out_len = w.len;
	return 0;
}

int jobd_decode_run_request(const uint8_t *buf, size_t len,
                              struct job *job,
                              char *err, size_t err_sz)
{
	struct agd_rd r;
	agd_rd_init(&r, buf, len);

	job_set_defaults(job);

	agd_rd_u64(&r, &job->memory_max);
	agd_rd_u64(&r, &job->memory_high);
	agd_rd_u64(&r, &job->swap_max);
	agd_rd_u64(&r, &job->cpu_max_q);
	agd_rd_u64(&r, &job->cpu_max_p);
	agd_rd_u64(&r, &job->timeout_ms);
	agd_rd_u32(&r, &job->cpu_weight);
	agd_rd_u32(&r, &job->pids_max);
	agd_rd_u32(&r, &job->io_weight);
	agd_rd_u8(&r, &job->network_mode);
	agd_rd_u8(&r, &job->fanotify_mode);
	agd_rd_u8(&r, &job->iouring_enabled);
	agd_rd_u8(&r, &job->dry_run);

	if (agd_rd_str(&r, job->id, sizeof(job->id)) != 0) {
		snprintf(err, err_sz, "malformed job ID field");
		return -1;
	}

	if (agd_rd_count(&r, JOBD_MAX_LAYERS, &job->layer_count) != 0) {
		snprintf(err, err_sz, "too many layers (max %u)", JOBD_MAX_LAYERS);
		return -1;
	}
	for (uint32_t i = 0; i < job->layer_count; i++) {
		if (agd_rd_str(&r, job->layers[i], JOBD_MAX_PATH_LEN) != 0) {
			snprintf(err, err_sz, "malformed layer %u", i);
			return -1;
		}
	}

	if (agd_rd_count(&r, JOBD_MAX_PATH_COUNT, &job->ro_count) != 0) {
		snprintf(err, err_sz, "too many --ro paths (max %u)",
		         JOBD_MAX_PATH_COUNT);
		return -1;
	}
	for (uint32_t i = 0; i < job->ro_count; i++) {
		if (agd_rd_str(&r, job->ro_paths[i], JOBD_MAX_PATH_LEN) != 0) {
			snprintf(err, err_sz, "malformed --ro path %u", i);
			return -1;
		}
	}

	if (agd_rd_count(&r, JOBD_MAX_PATH_COUNT, &job->rw_count) != 0) {
		snprintf(err, err_sz, "too many --rw paths (max %u)",
		         JOBD_MAX_PATH_COUNT);
		return -1;
	}
	for (uint32_t i = 0; i < job->rw_count; i++) {
		if (agd_rd_str(&r, job->rw_paths[i], JOBD_MAX_PATH_LEN) != 0) {
			snprintf(err, err_sz, "malformed --rw path %u", i);
			return -1;
		}
	}

	if (agd_rd_count(&r, JOBD_MAX_CANARIES, &job->canary_count) != 0) {
		snprintf(err, err_sz, "too many canaries (max %u)",
		         JOBD_MAX_CANARIES);
		return -1;
	}
	for (uint32_t i = 0; i < job->canary_count; i++) {
		if (agd_rd_str(&r, job->canaries[i], JOBD_MAX_PATH_LEN) != 0) {
			snprintf(err, err_sz, "malformed canary %u", i);
			return -1;
		}
	}

	if (agd_rd_count(&r, JOBD_MAX_MEMFD_INPUT,
	                 &job->memfd_input_count) != 0) {
		snprintf(err, err_sz, "too many memfd inputs (max %u)",
		         JOBD_MAX_MEMFD_INPUT);
		return -1;
	}
	for (uint32_t i = 0; i < job->memfd_input_count; i++) {
		if (agd_rd_str(&r, job->memfd_inputs[i].name,
		               JOBD_MAX_PATH_LEN) != 0 ||
		    agd_rd_str(&r, job->memfd_inputs[i].path,
		               JOBD_MAX_PATH_LEN) != 0) {
			snprintf(err, err_sz, "malformed memfd input %u", i);
			return -1;
		}
	}

	if (agd_rd_count(&r, JOBD_MAX_ALLOW_NET, &job->allow_net_count) != 0) {
		snprintf(err, err_sz, "too many --allow-net entries (max %u)",
		         JOBD_MAX_ALLOW_NET);
		return -1;
	}
	for (uint32_t i = 0; i < job->allow_net_count; i++) {
		if (agd_rd_str(&r, job->allow_net[i], JOBD_MAX_ALLOW_LEN) != 0) {
			snprintf(err, err_sz, "malformed --allow-net entry %u", i);
			return -1;
		}
	}

	uint32_t argc = 0;
	if (agd_rd_count(&r, JOBD_MAX_ARGV, &argc) != 0) {
		snprintf(err, err_sz, "too many arguments (max %u)", JOBD_MAX_ARGV);
		return -1;
	}
	for (uint32_t i = 0; i < argc; i++) {
		char arg[JOBD_MAX_ARG_LEN];
		if (agd_rd_str(&r, arg, sizeof(arg)) != 0) {
			snprintf(err, err_sz, "malformed argument %u", i);
			return -1;
		}
		if (job_add_arg(job, arg, err, err_sz) != 0)
			return -1;
	}

	uint32_t envc = 0;
	if (agd_rd_count(&r, JOBD_MAX_ENV_COUNT, &envc) != 0) {
		snprintf(err, err_sz, "too many environment entries (max %u)",
		         JOBD_MAX_ENV_COUNT);
		return -1;
	}
	for (uint32_t i = 0; i < envc; i++) {
		char kv[JOBD_MAX_ENV_LEN];
		if (agd_rd_str(&r, kv, sizeof(kv)) != 0) {
			snprintf(err, err_sz, "malformed environment entry %u", i);
			return -1;
		}
		if (job_add_env(job, kv, err, err_sz) != 0)
			return -1;
	}

	if (!agd_rd_ok(&r)) {
		snprintf(err, err_sz, "truncated run request");
		return -1;
	}
	if (r.off != r.len) {
		snprintf(err, err_sz, "trailing bytes in run request (%zu unread)",
		         r.len - r.off);
		return -1;
	}

	return 0;
}
