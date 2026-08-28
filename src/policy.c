#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "jobd.h"

static void section(struct agd_buf *b, const char *title)
{
	agd_buf_addf(b, "\n[%s]\n", title);
}

static void kv(struct agd_buf *b, const char *key, const char *fmt, ...)
{
	agd_buf_addf(b, "  %-24s = ", key);

	va_list ap;
	va_start(ap, fmt);
	agd_buf_vaddf(b, fmt, ap);
	va_end(ap);

	agd_buf_addch(b, '\n');
}

static const char *comp_or_missing(enum jobd_component c)
{
	const char *p = jobd_component_path(c);
	return p ? p : "(not found)";
}

int jobd_policy_plan_dryrun(const struct job *job,
                              char *output, size_t output_sz)
{
	struct agd_buf b;
	agd_buf_init(&b, output, output_sz);

	char err[512];
	if (job_validate(job, err, sizeof(err)) != 0) {
		agd_buf_addf(&b, "VALIDATION FAILED: %s\n", err);
		return 0;
	}

	const struct jobd_paths *p = jobd_paths();

	char job_dir[JOBD_PATH_LEN_LONG];
	char root[JOBD_PATH_LEN_LONG];
	char policy[JOBD_PATH_LEN_LONG];
	char logs[JOBD_PATH_LEN_LONG];
	jobd_job_dir(job->id, job_dir, sizeof(job_dir));
	jobd_job_subdir(job->id, "root", root, sizeof(root));
	jobd_job_subdir(job->id, "root/run/jobd/landlock.toml",
	                  policy, sizeof(policy));
	jobd_job_subdir(job->id, "logs", logs, sizeof(logs));

	agd_buf_adds(&b, "=== JOBD DRY-RUN PLAN ===\n");

	section(&b, "job");
	kv(&b, "id", "%s", job->id);
	kv(&b, "state", "%s", job_state_name(job->state));
	kv(&b, "dry_run", "%s", job->dry_run ? "yes" : "no");
	kv(&b, "job_dir", "%s", job_dir);
	kv(&b, "log_dir", "%s", logs);

	section(&b, "components");
	kv(&b, "cgroupctl", "%s", comp_or_missing(JOBD_COMP_CGROUPCTL));
	kv(&b, "job-init", "%s", comp_or_missing(JOBD_COMP_JOB_INIT));
	kv(&b, "sandbox", "%s", comp_or_missing(JOBD_COMP_SANDBOX));
	kv(&b, "landlockd", "%s", comp_or_missing(JOBD_COMP_LANDLOCKD));
	if (job->fanotify_mode != JOBD_FANOTIFY_OFF)
		kv(&b, "fanotifyd", "%s", comp_or_missing(JOBD_COMP_FANOTIFYD));
	if (job->memfd_input_count > 0)
		kv(&b, "memfdbus", "%s", comp_or_missing(JOBD_COMP_MEMFDBUS));
	if (job->iouring_enabled)
		kv(&b, "iouringd", "%s", comp_or_missing(JOBD_COMP_IOURINGD));

	section(&b, "overlay");
	for (uint32_t i = 0; i < job->layer_count; i++)
		kv(&b, "layer", "%s", job->layers[i]);
	kv(&b, "overlay_store", "%s", p->overlay_dir);
	kv(&b, "merged_root", "%s", root);

	section(&b, "landlock_paths");
	kv(&b, "policy_file", "%s", policy);
	kv(&b, "policy_file_inside", "/run/jobd/landlock.toml");

	if (job->ro_count == 0) {
		kv(&b, "allow_read_default", "/usr:/lib:/lib64:/bin");
	} else {
		for (uint32_t i = 0; i < job->ro_count; i++)
			kv(&b, "allow_read", "%s", job->ro_paths[i]);
	}
	for (uint32_t i = 0; i < job->rw_count; i++)
		kv(&b, "allow_write", "%s", job->rw_paths[i]);
	kv(&b, "allow_write_always", "/tmp:/workspace:/export");

	section(&b, "seccomp_deny");
	{
		const char *const *deny = job_seccomp_deny_list();
		for (int i = 0; deny[i]; i++)
			kv(&b, "deny_syscall", "%s", deny[i]);
	}

	section(&b, "cgroup_limits");
	kv(&b, "memory.max", "%llu", (unsigned long long)job->memory_max);
	kv(&b, "memory.high", "%llu", (unsigned long long)job->memory_high);
	kv(&b, "memory.swap.max", "%llu", (unsigned long long)job->swap_max);
	kv(&b, "cpu.max", "%llu %llu",
	   (unsigned long long)job->cpu_max_q, (unsigned long long)job->cpu_max_p);
	kv(&b, "cpu.weight", "%u", job->cpu_weight);
	kv(&b, "pids.max", "%u", job->pids_max);
	kv(&b, "io.weight", "%u", job->io_weight);
	kv(&b, "timeout_ms", "%llu", (unsigned long long)job->timeout_ms);

	section(&b, "network");
	kv(&b, "mode", "none");
	kv(&b, "namespace", "CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWNS");

	section(&b, "fanotify");
	switch (job->fanotify_mode) {
	case JOBD_FANOTIFY_OFF:     kv(&b, "mode", "off");     break;
	case JOBD_FANOTIFY_OBSERVE: kv(&b, "mode", "observe"); break;
	case JOBD_FANOTIFY_DENY:    kv(&b, "mode", "deny");    break;
	default:                      kv(&b, "mode", "?");       break;
	}
	if (job->fanotify_mode != JOBD_FANOTIFY_OFF) {
		kv(&b, "watch_path", "%s", root);
		kv(&b, "alert_log", "%s/fanotifyd.jsonl", logs);
		kv(&b, "on_alert", "%s",
		   job->fanotify_mode == JOBD_FANOTIFY_DENY
		           ? "freeze then kill the cgroup" : "record only");
	}
	for (uint32_t i = 0; i < job->canary_count; i++)
		kv(&b, "canary", "%s", job->canaries[i]);

	section(&b, "memfdbus");
	kv(&b, "enabled", "%s", job->memfd_input_count > 0 ? "yes" : "no");
	if (job->memfd_input_count > 0) {
		kv(&b, "broker_mode", "per-job");
		kv(&b, "socket_visible", "/run/jobd/memfdbus.sock");
		kv(&b, "socket_host", "%s/run/jobd/memfdbus.sock", root);
		for (uint32_t i = 0; i < job->memfd_input_count; i++)
			kv(&b, "input", "%s <- %s",
			   job->memfd_inputs[i].name, job->memfd_inputs[i].path);
	}

	section(&b, "iouringd");
	kv(&b, "enabled", "%s", job->iouring_enabled ? "yes" : "no");
	if (job->iouring_enabled) {
		kv(&b, "socket_visible", "/run/jobd/iouringd.sock");
		kv(&b, "socket_host", "%s/run/jobd/iouringd.sock", root);
		kv(&b, "ring_entries", "%s", JOBD_IOURING_RING_ENTRIES);
		kv(&b, "max_clients", "%s", JOBD_IOURING_MAX_CLIENTS);
		kv(&b, "per_client_credits", "%s", JOBD_IOURING_CREDITS);
		kv(&b, "io_bytes_max", "%s", JOBD_IOURING_IO_BYTES_MAX);
	}

	section(&b, "argv_chain");
	kv(&b, "1_cgroupctl", "%s run --id %s ... --",
	   comp_or_missing(JOBD_COMP_CGROUPCTL), job->id);
	kv(&b, "2_job_init", "%s --root %s --network none --",
	   comp_or_missing(JOBD_COMP_JOB_INIT), root);
	kv(&b, "3_sandbox", "%s %s /usr/bin/landlockd --existing-rootfs",
	   comp_or_missing(JOBD_COMP_SANDBOX), root);
	kv(&b, "4_landlockd", "run --policy-file /run/jobd/landlock.toml --");

	{
		size_t off = 0;
		for (uint32_t i = 0; i < job->argc && off < job->argv_bytes; i++) {
			const char *arg = job->argv_buf + off;
			char label[32];
			snprintf(label, sizeof(label), "5_argv[%u]", i);
			kv(&b, label, "%s", arg);
			off += strlen(arg) + 1;
		}
	}

	section(&b, "environment");
	{
		char  env_buf[JOBD_ENV_BYTES + 2048];
		char *env_v[JOBD_MAX_ENV_COUNT + 16];
		int   n = job_build_launch_env(job, env_buf, sizeof(env_buf),
		                                 env_v,
		                                 JOBD_MAX_ENV_COUNT + 16,
		                                 err, sizeof(err));
		if (n < 0) {
			kv(&b, "error", "%s", err);
		} else {
			for (int i = 0; i < n; i++)
				kv(&b, "env", "%s", env_v[i]);
		}
	}

	section(&b, "cleanup_plan");
	kv(&b, "on_exit", "stop iouringd, memfdbus, fanotifyd; kill and "
	                  "remove the cgroup; keep logs");
	kv(&b, "on_cleanup", "unmount the root, remove %s", job_dir);

	section(&b, "security_downgrade_rules");
	kv(&b, "sandbox_namespaces", "required");
	kv(&b, "network_namespace", "required");
	kv(&b, "landlock", "required");
	kv(&b, "seccomp", "required");
	kv(&b, "cgroup_limits", "required");
	kv(&b, "fanotify", "%s",
	   job->fanotify_mode == JOBD_FANOTIFY_OFF ? "disabled" : "required");
	kv(&b, "memfdbus", "%s",
	   job->memfd_input_count > 0 ? "required" : "disabled");
	kv(&b, "iouringd", "%s", job->iouring_enabled ? "required" : "disabled");

	agd_buf_adds(&b, "\n=== END DRY-RUN PLAN ===\n");

	if (agd_buf_truncated(&b))
		agd_buf_adds(&b, "\n(plan truncated)\n");

	return 0;
}
