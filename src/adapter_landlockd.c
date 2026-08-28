#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "jobd.h"

static const char *const seccomp_deny[] = {
	"ptrace", "bpf", "perf_event_open",
	"kexec_load", "init_module", "finit_module", "delete_module",
	"reboot", "swapon", "swapoff",
	"mount", "umount2", "pivot_root", "open_tree", "move_mount",
	"fsopen", "fsconfig", "fsmount", "mount_setattr",
	"open_by_handle_at",
	"unshare", "setns",
	NULL
};

const char *const *job_seccomp_deny_list(void)
{
	return seccomp_deny;
}

#define RO_ACCESS "[\"execute\", \"read_file\", \"read_dir\"]"
#define RW_ACCESS "[\"write_file\", \"read_file\", \"read_dir\", " \
                  "\"make_dir\", \"make_reg\", \"remove_file\", " \
                  "\"remove_dir\", \"truncate\"]"

static void emit_rule(struct agd_buf *b, const char *path, const char *access)
{
	agd_buf_adds(b, "\n  [[fs_layer.rule]]\n  path = \"");
	agd_buf_add_toml(b, path);
	agd_buf_adds(b, "\"\n  allowed_access = ");
	agd_buf_adds(b, access);
	agd_buf_addch(b, '\n');
}

static int dir_exists_in_root(const char *root, const char *inside)
{
	char chk[JOBD_PATH_LEN_LONG];
	int n = snprintf(chk, sizeof(chk), "%s%s", root, inside);
	if (n < 0 || (size_t)n >= sizeof(chk))
		return 0;

	struct stat st;
	return stat(chk, &st) == 0 && S_ISDIR(st.st_mode);
}

int job_landlock_generate_policy(const struct job *job,
                                   const char *policy_path,
                                   char *errmsg, size_t errmsg_sz)
{
	char  text[128 * 1024];
	struct agd_buf b;
	agd_buf_init(&b, text, sizeof(text));

	agd_buf_adds(&b, "version = 1\n\n[[fs_layer]]\n");
	agd_buf_adds(&b,
	             "handled_access_fs = [\"execute\", \"read_file\", "
	             "\"read_dir\", \"write_file\", \"make_dir\", \"make_reg\", "
	             "\"remove_file\", \"remove_dir\", \"truncate\"]\n");

	if (job->ro_count > 0) {
		for (uint32_t i = 0; i < job->ro_count; i++) {
			if (dir_exists_in_root(job->root_path, job->ro_paths[i]))
				emit_rule(&b, job->ro_paths[i], RO_ACCESS);
		}
	} else {
		static const char *defaults[] = {
			"/usr", "/lib", "/lib64", "/bin", NULL
		};
		for (int i = 0; defaults[i]; i++) {
			if (dir_exists_in_root(job->root_path, defaults[i]))
				emit_rule(&b, defaults[i], RO_ACCESS);
		}
	}

	for (uint32_t i = 0; i < job->rw_count; i++) {
		if (dir_exists_in_root(job->root_path, job->rw_paths[i]))
			emit_rule(&b, job->rw_paths[i], RW_ACCESS);
	}

	emit_rule(&b, "/tmp", RW_ACCESS);
	emit_rule(&b, "/workspace", RW_ACCESS);
	emit_rule(&b, "/export", RW_ACCESS);

	emit_rule(&b, "/dev",
	          "[\"read_file\", \"write_file\", \"read_dir\", \"truncate\"]");

	agd_buf_adds(&b, "\n[seccomp]\ndeny = [");
	for (int i = 0; seccomp_deny[i]; i++) {
		if (i > 0)
			agd_buf_adds(&b, ", ");
		agd_buf_addch(&b, '"');
		agd_buf_add_toml(&b, seccomp_deny[i]);
		agd_buf_addch(&b, '"');
	}
	agd_buf_adds(&b, "]\nerrno = 1\n");

	if (agd_buf_truncated(&b)) {
		snprintf(errmsg, errmsg_sz,
		         "generated policy exceeds %zu bytes", sizeof(text));
		return -1;
	}

	char tmp_path[JOBD_PATH_LEN_LONG];
	int n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", policy_path);
	if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
		snprintf(errmsg, errmsg_sz, "policy path too long");
		return -1;
	}

	int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC |
	              O_NOFOLLOW, 0644);
	if (fd < 0) {
		snprintf(errmsg, errmsg_sz, "cannot open %s: %s",
		         tmp_path, strerror(errno));
		return -1;
	}

	size_t len = agd_buf_len(&b);
	if (jobd_write_full(fd, text, len) != 0) {
		snprintf(errmsg, errmsg_sz, "cannot write %s: %s",
		         tmp_path, strerror(errno));
		close(fd);
		unlink(tmp_path);
		return -1;
	}
	if (fsync(fd) != 0) {
		snprintf(errmsg, errmsg_sz, "cannot flush %s: %s",
		         tmp_path, strerror(errno));
		close(fd);
		unlink(tmp_path);
		return -1;
	}
	close(fd);

	if (rename(tmp_path, policy_path) != 0) {
		snprintf(errmsg, errmsg_sz, "cannot install %s: %s",
		         policy_path, strerror(errno));
		unlink(tmp_path);
		return -1;
	}

	snprintf(errmsg, errmsg_sz, "policy written to %s", policy_path);
	return 0;
}
