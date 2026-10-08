#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/un.h>

#include "jobd.h"
#include "testutil.h"

static void test_job_id_path_traversal(void)
{
	TEST("job IDs rejecting path traversal");

	char err[256];
	const char *bad[] = {
		"../etc", "dir/../etc", "/etc", ".", "..", "a/b", "./x", NULL
	};

	for (int i = 0; bad[i]; i++) {
		if (job_id_validate(bad[i], err, sizeof(err)) == 0) {
			FAIL(bad[i]);
			return;
		}
	}
	PASS();
}

static void test_job_id_special_chars(void)
{
	TEST("job IDs rejecting shell and control characters");

	char err[256];
	const char *bad[] = {
		"job\nid", "job\tid", "job\rid", "job\vid",
		"hello world", "job;id", "job|id", "job&id",
		"job$id", "job`id`", "job(id)", "job[id]",
		"job{id}", "job<id>", "job#id", "job!id",
		"job@id", "job^id", "job~id", "job%id",
		"job\"id", "job'id", "job\\id", "job\xffid",
		NULL
	};

	for (int i = 0; bad[i]; i++) {
		if (job_id_validate(bad[i], err, sizeof(err)) == 0) {
			FAIL(bad[i]);
			return;
		}
	}
	PASS();
}

static void test_job_id_length(void)
{
	TEST("job ID length bounds");

	char err[256];
	char exact[JOBD_MAX_JOB_ID + 1];
	memset(exact, 'a', JOBD_MAX_JOB_ID);
	exact[JOBD_MAX_JOB_ID] = '\0';
	ASSERT(job_id_validate(exact, err, sizeof(err)) == 0,
	       "the maximum length should be accepted");

	char over[JOBD_MAX_JOB_ID + 2];
	memset(over, 'a', JOBD_MAX_JOB_ID + 1);
	over[JOBD_MAX_JOB_ID + 1] = '\0';
	ASSERT(job_id_validate(over, err, sizeof(err)) != 0,
	       "one byte over the maximum should be rejected");

	ASSERT(job_id_validate("", err, sizeof(err)) != 0,
	       "an empty ID should be rejected");
	ASSERT(job_id_validate(NULL, err, sizeof(err)) != 0,
	       "a NULL ID should be rejected");
	PASS();
}

static void test_policy_injection_is_escaped(void)
{
	TEST("policy injection through a path is neutralised");

	char store[512];
	struct agd_buf b;
	agd_buf_init(&b, store, sizeof(store));

	agd_buf_adds(&b, "  path = \"");
	agd_buf_add_toml(&b,
	                 "/workspace\"]\n\n  [[fs_layer.rule]]\n"
	                 "  path = \"/\"\n  allowed_access = [\"write_file\"");
	agd_buf_adds(&b, "\"\n");

	int rule_count = 0;
	for (const char *p = store; (p = strstr(p, "path = \"")); p += 8)
		rule_count++;

	ASSERT(rule_count == 1, "escaping should leave exactly one rule");
	ASSERT(strchr(store + 10, '\n') == store + strlen(store) - 1,
	       "no embedded newline should survive");
	PASS();
}

static void test_unterminated_job_id_payload(void)
{
	TEST("job ID payload without a terminator is bounded");

	char jid[JOBD_MAX_JOB_ID + 1];
	uint8_t payload[16];
	memset(payload, 'a', sizeof(payload));

	size_t len = sizeof(payload);
	ASSERT(len < sizeof(jid), "test setup");

	memcpy(jid, payload, len);
	jid[len] = '\0';

	char err[256];
	ASSERT(strlen(jid) == len, "length must come from the header");
	ASSERT(job_id_validate(jid, err, sizeof(err)) == 0,
	       "a bounded copy should validate");
	PASS();
}

static void test_oversized_protocol_payload(void)
{
	TEST("oversized payload indicator is rejected");

	int fds[2];
	ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair");

	struct jobd_msg_header hdr = {
		.magic       = JOBD_PROTO_MAGIC,
		.version     = JOBD_PROTO_VERSION,
		.type        = JOBD_MSG_RUN,
		.payload_len = 0xFFFFFFFFu,
		.request_id  = 1,
	};
	jobd_send_msg(fds[0], &hdr, NULL);

	struct jobd_msg_header rhdr;
	uint8_t buf[16];
	ASSERT(jobd_recv_msg(fds[1], &rhdr, buf, sizeof(buf), NULL) == -4,
	       "should reject a huge payload_len");

	close(fds[0]);
	close(fds[1]);
	PASS();
}

static void test_hostile_run_request(void)
{
	TEST("hostile run request is rejected");

	uint8_t *buf = calloc(1, JOBD_MAX_PAYLOAD);
	ASSERT(buf != NULL, "allocation");

	const uint32_t counts[] = { 1023, 65535, 16777216u, 0xFFFFFFFFu };

	for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++) {
		struct agd_wr w;
		agd_wr_init(&w, buf, JOBD_MAX_PAYLOAD);

		for (int i = 0; i < 6; i++)
			agd_wr_u64(&w, 0);
		for (int i = 0; i < 3; i++)
			agd_wr_u32(&w, 1);
		for (int i = 0; i < 4; i++)
			agd_wr_u8(&w, 0);
		agd_wr_str(&w, "hostile");
		agd_wr_u32(&w, counts[c]);

		for (int i = 0; i < 200 && agd_wr_ok(&w); i++)
			agd_wr_str(&w, "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

		struct job job;
		char err[512];
		if (jobd_decode_run_request(buf, w.len, &job,
		                              err, sizeof(err)) == 0) {
			free(buf);
			FAIL("decoder accepted an oversized count");
			return;
		}
	}

	free(buf);
	PASS();
}

static void test_dryrun_output_is_bounded(void)
{
	TEST("dry-run output stays inside a small buffer");

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "bounded");
	job_add_arg(&job, "/bin/true", err, sizeof(err));

	for (uint32_t i = 0; i < JOBD_MAX_PATH_COUNT; i++) {
		snprintf(job.ro_paths[i], JOBD_MAX_PATH_LEN,
		         "/read/only/path/number/%u/with/some/extra/length", i);
		snprintf(job.rw_paths[i], JOBD_MAX_PATH_LEN,
		         "/read/write/path/number/%u/with/some/extra/length", i);
	}
	job.ro_count = JOBD_MAX_PATH_COUNT;
	job.rw_count = JOBD_MAX_PATH_COUNT;

	char small[512];
	char canary[64];
	memset(canary, 0x5a, sizeof(canary));

	ASSERT(jobd_policy_plan_dryrun(&job, small, sizeof(small)) == 0,
	       "dry run should succeed");
	ASSERT(strlen(small) < sizeof(small), "output must stay in bounds");

	for (size_t i = 0; i < sizeof(canary); i++)
		ASSERT(canary[i] == 0x5a, "dry run wrote past its buffer");
	PASS();
}

static void test_doctor_output_is_bounded(void)
{
	TEST("doctor output stays inside a small buffer");

	char small[256];
	char canary[64];
	memset(canary, 0x5a, sizeof(canary));

	ASSERT(jobd_doctor(small, sizeof(small)) == 0, "doctor should succeed");
	ASSERT(strlen(small) < sizeof(small), "output must stay in bounds");

	for (size_t i = 0; i < sizeof(canary); i++)
		ASSERT(canary[i] == 0x5a, "doctor wrote past its buffer");
	PASS();
}

static void test_env_is_not_inherited(void)
{
	TEST("the workload environment is not inherited from the host");

	setenv("SECRET_TOKEN", "must-not-leak", 1);
	setenv("AWS_SECRET_ACCESS_KEY", "must-not-leak", 1);

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "envtest");
	job_add_arg(&job, "/bin/true", err, sizeof(err));

	char  buf[JOBD_ENV_BYTES + 2048];
	char *env[JOBD_MAX_ENV_COUNT + 16];
	int n = job_build_launch_env(&job, buf, sizeof(buf), env,
	                               JOBD_MAX_ENV_COUNT + 16,
	                               err, sizeof(err));
	ASSERT(n > 0, err);

	for (int i = 0; i < n; i++) {
		if (strstr(env[i], "must-not-leak")) {
			FAIL("a host environment variable leaked");
			return;
		}
	}
	PASS();
}

static void test_env_override(void)
{
	TEST("a client entry overrides the matching default");

	struct job job;
	char err[256];
	job_set_defaults(&job);
	snprintf(job.id, sizeof(job.id), "envover");
	job_add_arg(&job, "/bin/true", err, sizeof(err));
	job_add_env(&job, "PATH=/custom/bin", err, sizeof(err));

	char  buf[JOBD_ENV_BYTES + 2048];
	char *env[JOBD_MAX_ENV_COUNT + 16];
	int n = job_build_launch_env(&job, buf, sizeof(buf), env,
	                               JOBD_MAX_ENV_COUNT + 16,
	                               err, sizeof(err));
	ASSERT(n > 0, err);

	int path_count = 0;
	for (int i = 0; i < n; i++) {
		if (strncmp(env[i], "PATH=", 5) == 0) {
			path_count++;
			ASSERT(strcmp(env[i], "PATH=/custom/bin") == 0,
			       "the override should win");
		}
	}
	ASSERT(path_count == 1, "PATH should appear exactly once");
	PASS();
}

static char g_tmp[64];
static char g_root[128], g_ext[128], g_host[128];
static char g_bin[256], g_landlockd[256], g_helper[256], g_dep[256];
static char g_err[512];
static struct job g_job;

static int  g_mknod_count, g_mknod_confined;
static char g_trap_name[64], g_trap_parent[512], g_trap_moved[512];
static int  g_trap_fired;

#define SENTINEL  "external sentinel\n"
#define WORKLOAD  "#!/bin/sh\necho workload\n"
#define LANDLOCKD "landlockd stand-in\n"
#define HELPER    "policy helper stand-in\n"
#define DEP       "dependency stand-in\n"

int __wrap_job_elf_resolve_deps(const char *binary, struct job_elf_deps *out,
                                char *err, size_t err_sz)
{
	(void)err; (void)err_sz;
	memset(out, 0, sizeof(*out));
	if (g_dep[0] && strcmp(binary, g_job.argv_buf) == 0) {
		snprintf(out->paths[0], sizeof(out->paths[0]), "%s", g_dep);
		out->count = 1;
	}
	return 0;
}

/* Stands in for mknod without CAP_MKNOD: records whether the call was
 * anchored to the root's real dev directory and leaves a placeholder. */
int __wrap_mknodat(int dirfd, const char *path, mode_t mode, dev_t dev)
{
	struct stat dir_st, dev_st;
	char devdir[sizeof(g_root) + 4];
	snprintf(devdir, sizeof(devdir), "%s/dev", g_root);
	g_mknod_count++;
	if (fstat(dirfd, &dir_st) != 0 || lstat(devdir, &dev_st) != 0 ||
	    dir_st.st_dev != dev_st.st_dev || dir_st.st_ino != dev_st.st_ino ||
	    strchr(path, '/') || !S_ISCHR(mode) || major(dev) == 0)
		g_mknod_confined = 0;
	int fd = openat(dirfd, path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
	                mode & 07777);
	if (fd < 0)
		return -1;
	close(fd);
	return 0;
}

int __real_unlinkat(int dirfd, const char *path, int flags);

/* Swaps the destination's parent for a symlink out of the root after
 * staging has validated it and right before the file is created. */
int __wrap_unlinkat(int dirfd, const char *path, int flags)
{
	if (g_trap_name[0] && !g_trap_fired && strcmp(path, g_trap_name) == 0)
		g_trap_fired = rename(g_trap_parent, g_trap_moved) == 0 &&
		               symlink(g_ext, g_trap_parent) == 0 ? 1 : -1;
	return __real_unlinkat(dirfd, path, flags);
}

static int make_dirs(const char *path)
{
	char tmp[256];
	int n = snprintf(tmp, sizeof(tmp), "%s", path);
	if (n < 0 || (size_t)n >= sizeof(tmp))
		return -1;
	for (char *p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, 0755) != 0 && errno != EEXIST)
			return -1;
		*p = '/';
	}
	return mkdir(tmp, 0755) == 0 || errno == EEXIST ? 0 : -1;
}

static int write_file(const char *path, const char *content, mode_t mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	ssize_t len = (ssize_t)strlen(content);
	int ok = write(fd, content, (size_t)len) == len &&
	         fchmod(fd, mode) == 0;
	close(fd);
	return ok ? 0 : -1;
}

static int file_is(const char *path, const char *content, mode_t mode)
{
	struct stat st;
	char buf[256];
	if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) ||
	    (st.st_mode & 07777) != mode)
		return 0;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	ssize_t got = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (got < 0)
		return 0;
	buf[got] = '\0';
	return strcmp(buf, content) == 0;
}

static int make_sentinel(const char *path)
{
	return write_file(path, SENTINEL, 0600);
}

static int sentinel_intact(const char *path)
{
	struct stat st;
	return file_is(path, SENTINEL, 0600) && lstat(path, &st) == 0 &&
	       st.st_nlink == 1;
}

static int entry_count(const char *dir)
{
	DIR *d = opendir(dir);
	if (!d)
		return -1;
	int n = 0;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (strcmp(e->d_name, ".") != 0 && strcmp(e->d_name, "..") != 0)
			n++;
	}
	closedir(d);
	return n;
}

static int same_inode(const char *a, const char *b)
{
	struct stat sa, sb;
	return lstat(a, &sa) == 0 && lstat(b, &sb) == 0 &&
	       sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static int rm_entry(const char *path, const struct stat *st, int type,
                    struct FTW *ftw)
{
	(void)st; (void)type; (void)ftw;
	return remove(path);
}

static void teardown_root(void)
{
	nftw(g_tmp, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
}

static int set_workload(const char *path)
{
	char err[256];
	job_set_defaults(&g_job);
	snprintf(g_job.id, sizeof(g_job.id), "rootfs");
	snprintf(g_job.root_path, sizeof(g_job.root_path), "%s", g_root);
	return job_add_arg(&g_job, path, err, sizeof(err));
}

static int setup_root(void)
{
	char err[256], hostbin[160];
	snprintf(g_tmp, sizeof(g_tmp), "/tmp/jobd-rootfs-XXXXXX");
	if (!mkdtemp(g_tmp))
		return -1;
	snprintf(g_root, sizeof(g_root), "%s/job/root", g_tmp);
	snprintf(g_ext, sizeof(g_ext), "%s/ext", g_tmp);
	snprintf(g_host, sizeof(g_host), "%s/host", g_tmp);
	snprintf(hostbin, sizeof(hostbin), "%s/bin", g_host);
	snprintf(g_bin, sizeof(g_bin), "%s/workload", hostbin);
	snprintf(g_landlockd, sizeof(g_landlockd), "%s/landlockd", g_host);
	snprintf(g_helper, sizeof(g_helper), "%s/landlockd-policy-helper",
	         g_host);

	g_dep[0] = '\0';
	g_err[0] = '\0';
	g_mknod_count = 0;
	g_mknod_confined = 1;
	g_trap_name[0] = '\0';
	g_trap_fired = 0;

	if (make_dirs(g_root) != 0 || make_dirs(g_ext) != 0 ||
	    make_dirs(hostbin) != 0 ||
	    write_file(g_bin, WORKLOAD, 0755) != 0 ||
	    write_file(g_landlockd, LANDLOCKD, 0755) != 0 ||
	    write_file(g_helper, HELPER, 0755) != 0 ||
	    jobd_config_set("landlockd", g_landlockd, err, sizeof(err)) != 0 ||
	    jobd_config_set("landlockd-policy-helper", g_helper,
	                    err, sizeof(err)) != 0)
		return -1;
	return set_workload(g_bin);
}

static int prepare(void)
{
	return job_rootfs_prepare(&g_job, g_err, sizeof(g_err));
}

/* Where a path lands when staged into the job root. */
static void staged(char *out, size_t out_sz, const char *inside)
{
	snprintf(out, out_sz, "%s%s", g_root, inside);
}

static void test_rootfs_parent_symlink(void)
{
	TEST("rootfs staging through a parent symlink stays in the root");

	ASSERT(setup_root() == 0, "fixture");
	char usr[256], bin[256], sentinel[256];
	staged(usr, sizeof(usr), "/usr");
	staged(bin, sizeof(bin), "/usr/bin");
	snprintf(sentinel, sizeof(sentinel), "%s/landlockd", g_ext);
	ASSERT(make_dirs(usr) == 0 && symlink(g_ext, bin) == 0 &&
	       make_sentinel(sentinel) == 0, "fixture");

	int rc = prepare();
	int intact = sentinel_intact(sentinel) && entry_count(g_ext) == 1;
	teardown_root();
	ASSERT(rc != 0, "a parent symlink leaving the root was accepted");
	ASSERT(intact, "the external file was written through the symlink");
	ASSERT(strstr(g_err, "usr/bin") != NULL, g_err);
	PASS();
}

static void test_rootfs_dependency_parent_symlink(void)
{
	TEST("an optional dependency behind a parent symlink fails setup");

	ASSERT(setup_root() == 0, "fixture");
	char vendor[256], in_tmp[512], in_vendor[512], sentinel[256];
	snprintf(vendor, sizeof(vendor), "%s/vendor", g_tmp);
	snprintf(g_dep, sizeof(g_dep), "%s/vendor/libdep.so", g_tmp);
	staged(in_tmp, sizeof(in_tmp), g_tmp);
	staged(in_vendor, sizeof(in_vendor), vendor);
	snprintf(sentinel, sizeof(sentinel), "%s/libdep.so", g_ext);
	ASSERT(make_dirs(vendor) == 0 && write_file(g_dep, DEP, 0755) == 0 &&
	       make_dirs(in_tmp) == 0 && symlink(g_ext, in_vendor) == 0 &&
	       make_sentinel(sentinel) == 0, "fixture");

	int rc = prepare();
	int intact = sentinel_intact(sentinel) && entry_count(g_ext) == 1;
	teardown_root();
	ASSERT(rc != 0, "a containment failure on a dependency was ignored");
	ASSERT(intact, "the external file was written through the symlink");
	ASSERT(strstr(g_err, "vendor") != NULL, g_err);
	PASS();
}

static void test_rootfs_destination_symlink(void)
{
	TEST("a symlinked destination is replaced, not written through");

	ASSERT(setup_root() == 0, "fixture");
	char bin[256], dst[256], sentinel[256];
	staged(bin, sizeof(bin), "/usr/bin");
	staged(dst, sizeof(dst), "/usr/bin/landlockd");
	snprintf(sentinel, sizeof(sentinel), "%s/landlockd", g_ext);
	ASSERT(make_dirs(bin) == 0 && make_sentinel(sentinel) == 0 &&
	       symlink(sentinel, dst) == 0, "fixture");

	int rc = prepare();
	int intact = sentinel_intact(sentinel);
	int replaced = file_is(dst, LANDLOCKD, 0755);
	teardown_root();
	ASSERT(rc == 0, g_err);
	ASSERT(intact, "the symlink target outside the root was modified");
	ASSERT(replaced, "the destination is not a fresh regular file");
	PASS();
}

static void test_rootfs_dotdot_traversal(void)
{
	TEST("'..' in staged paths cannot climb out of the job root");

	ASSERT(setup_root() == 0, "fixture");
	char bin_sentinel[256], dep_sentinel[256], path[320], copy[512];
	snprintf(bin_sentinel, sizeof(bin_sentinel), "%s/workload", g_ext);
	snprintf(dep_sentinel, sizeof(dep_sentinel), "%s/libdep.so", g_ext);
	ASSERT(make_sentinel(bin_sentinel) == 0 &&
	       make_sentinel(dep_sentinel) == 0, "fixture");
	/* Resolves to the sentinel on the host, and far above the root once
	 * the root path is merely prepended. */
	snprintf(path, sizeof(path), "/etc/../../../../../../..%s",
	         bin_sentinel);
	ASSERT(set_workload(path) == 0, "fixture");
	snprintf(g_dep, sizeof(g_dep), "/etc/../../../../../../..%s/libdep.so",
	         g_ext);

	int rc = prepare();
	int intact = sentinel_intact(bin_sentinel) &&
	             sentinel_intact(dep_sentinel);
	staged(copy, sizeof(copy), bin_sentinel);
	int bin_staged = file_is(copy, SENTINEL, 0600);
	staged(copy, sizeof(copy), dep_sentinel);
	int dep_staged = file_is(copy, SENTINEL, 0600);
	teardown_root();
	ASSERT(rc == 0, g_err);
	ASSERT(intact, "an external file was reached through '..'");
	ASSERT(bin_staged && dep_staged, "the copies did not land in the root");
	PASS();
}

static void test_rootfs_non_directory_parent(void)
{
	TEST("a non-directory where a root directory belongs fails setup");

	ASSERT(setup_root() == 0, "fixture");
	char run[256];
	staged(run, sizeof(run), "/run");
	ASSERT(write_file(run, "not a directory\n", 0644) == 0, "fixture");

	int rc = prepare();
	teardown_root();
	ASSERT(rc != 0, "a missing run/jobd directory was ignored");
	ASSERT(strstr(g_err, "run") && strstr(g_err, "Not a directory"), g_err);
	PASS();
}

static void test_rootfs_hardlinked_destination(void)
{
	TEST("a destination hard-linked outside the root is not reused");

	ASSERT(setup_root() == 0, "fixture");
	char bin[256], dst[256], sentinel[256];
	staged(bin, sizeof(bin), "/usr/bin");
	staged(dst, sizeof(dst), "/usr/bin/landlockd");
	snprintf(sentinel, sizeof(sentinel), "%s/landlockd", g_ext);
	ASSERT(make_dirs(bin) == 0 && make_sentinel(sentinel) == 0 &&
	       link(sentinel, dst) == 0, "fixture");

	int rc = prepare();
	int intact = sentinel_intact(sentinel);
	int fresh = file_is(dst, LANDLOCKD, 0755) && !same_inode(dst, sentinel);
	teardown_root();
	ASSERT(rc == 0, g_err);
	ASSERT(intact, "the shared inode was truncated or chmodded");
	ASSERT(fresh, "the destination is not a separate new file");
	PASS();
}

static void test_rootfs_device_dir_symlink(void)
{
	TEST("device setup behind a symlinked dev directory fails setup");

	ASSERT(setup_root() == 0, "fixture");
	char dev[256], sentinel[256];
	staged(dev, sizeof(dev), "/dev");
	snprintf(sentinel, sizeof(sentinel), "%s/null", g_ext);
	ASSERT(symlink(g_ext, dev) == 0 && make_sentinel(sentinel) == 0,
	       "fixture");

	int rc = prepare();
	int intact = sentinel_intact(sentinel) && entry_count(g_ext) == 1;
	int nodes = g_mknod_count;
	teardown_root();
	ASSERT(rc != 0, "a dev directory leaving the root was accepted");
	ASSERT(intact && nodes == 0, "device setup reached outside the root");
	ASSERT(strstr(g_err, "dev") != NULL, g_err);
	PASS();
}

static void test_rootfs_devices_confined(void)
{
	TEST("device nodes are created relative to the root's dev directory");

	ASSERT(setup_root() == 0, "fixture");
	char dev[256], null[256], sentinel[256];
	staged(dev, sizeof(dev), "/dev");
	staged(null, sizeof(null), "/dev/null");
	snprintf(sentinel, sizeof(sentinel), "%s/null", g_ext);
	ASSERT(make_dirs(dev) == 0 && make_sentinel(sentinel) == 0 &&
	       link(sentinel, null) == 0, "fixture");

	int rc = prepare();
	int intact = sentinel_intact(sentinel);
	int node = file_is(null, "", 0666) && !same_inode(null, sentinel);
	int count = g_mknod_count, confined = g_mknod_confined;
	teardown_root();
	ASSERT(rc == 0, g_err);
	ASSERT(count == 6 && confined, "mknod was not anchored to dev");
	ASSERT(intact, "the hard-linked external inode was modified");
	ASSERT(node, "the node did not get its final mode at creation");
	PASS();
}

static void test_rootfs_copy_preserves_modes(void)
{
	TEST("staged copies keep contents and modes, also via host symlinks");

	ASSERT(setup_root() == 0, "fixture");
	char real[256], copy[512];
	snprintf(real, sizeof(real), "%s/libdep-real.so", g_host);
	snprintf(g_dep, sizeof(g_dep), "%s/libdep.so", g_host);
	ASSERT(write_file(real, DEP, 0750) == 0 && symlink(real, g_dep) == 0,
	       "fixture");

	mode_t old = umask(077);
	int rc = prepare();
	umask(old);
	staged(copy, sizeof(copy), g_bin);
	int bin_ok = file_is(copy, WORKLOAD, 0755);
	staged(copy, sizeof(copy), g_dep);
	int dep_ok = file_is(copy, DEP, 0750);
	staged(copy, sizeof(copy), "/usr/bin/landlockd");
	int landlockd_ok = file_is(copy, LANDLOCKD, 0755);
	staged(copy, sizeof(copy), "/usr/bin/landlockd-policy-helper");
	int helper_ok = file_is(copy, HELPER, 0755);
	teardown_root();
	ASSERT(rc == 0, g_err);
	ASSERT(bin_ok, "the workload lost its contents or executable mode");
	ASSERT(dep_ok, "a symlinked dependency was not copied as a plain file");
	ASSERT(landlockd_ok && helper_ok, "components lost contents or modes");
	PASS();
}

static void test_rootfs_in_root_symlink(void)
{
	TEST("a symlink inside the root resolves inside the root");

	ASSERT(setup_root() == 0, "fixture");
	char in_tmp[256], in_host[256], opt[256], copy[512];
	staged(in_tmp, sizeof(in_tmp), g_tmp);
	staged(in_host, sizeof(in_host), g_host);
	staged(opt, sizeof(opt), "/opt/host");
	ASSERT(make_dirs(in_tmp) == 0 && make_dirs(opt) == 0 &&
	       symlink("/opt/host", in_host) == 0, "fixture");

	int rc = prepare();
	snprintf(copy, sizeof(copy), "%s/bin/workload", opt);
	int ok = file_is(copy, WORKLOAD, 0755);
	teardown_root();
	ASSERT(rc == 0, g_err);
	ASSERT(ok, "the workload did not land where the sandbox will look");
	PASS();
}

static void test_rootfs_parent_substitution(void)
{
	TEST("swapping a validated parent for a symlink does not redirect staging");

	ASSERT(setup_root() == 0, "fixture");
	char vendor[256], moved[256], dep_moved[256], sentinel[256], copy[512];
	snprintf(vendor, sizeof(vendor), "%s/vendor", g_tmp);
	snprintf(moved, sizeof(moved), "%s/vendor.moved", g_tmp);
	snprintf(dep_moved, sizeof(dep_moved), "%s/vendor.moved/libdep.so",
	         g_tmp);
	snprintf(g_dep, sizeof(g_dep), "%s/vendor/libdep.so", g_tmp);
	snprintf(sentinel, sizeof(sentinel), "%s/libdep.so", g_ext);
	staged(g_trap_parent, sizeof(g_trap_parent), vendor);
	staged(g_trap_moved, sizeof(g_trap_moved), moved);
	snprintf(g_trap_name, sizeof(g_trap_name), "libdep.so");
	ASSERT(make_dirs(vendor) == 0 && write_file(g_dep, DEP, 0755) == 0 &&
	       make_sentinel(sentinel) == 0, "fixture");

	int rc = prepare();
	struct stat st;
	int swapped = g_trap_fired == 1 && lstat(g_trap_parent, &st) == 0 &&
	              S_ISLNK(st.st_mode);
	int intact = sentinel_intact(sentinel) && entry_count(g_ext) == 1;
	staged(copy, sizeof(copy), dep_moved);
	int anchored = file_is(copy, DEP, 0755);
	teardown_root();
	ASSERT(swapped, "the parent was not swapped between validation and use");
	ASSERT(rc == 0, g_err);
	ASSERT(intact, "staging followed the substituted parent out of the root");
	ASSERT(anchored, "the file was not written via the validated descriptor");
	PASS();
}

int main(void)
{
	printf("=== adversarial / edge-case tests ===\n\n");

	test_job_id_path_traversal();
	test_job_id_special_chars();
	test_job_id_length();
	test_policy_injection_is_escaped();
	test_unterminated_job_id_payload();
	test_oversized_protocol_payload();
	test_hostile_run_request();
	test_dryrun_output_is_bounded();
	test_doctor_output_is_bounded();
	test_env_is_not_inherited();
	test_env_override();
	test_rootfs_parent_symlink();
	test_rootfs_dependency_parent_symlink();
	test_rootfs_destination_symlink();
	test_rootfs_dotdot_traversal();
	test_rootfs_non_directory_parent();
	test_rootfs_hardlinked_destination();
	test_rootfs_device_dir_symlink();
	test_rootfs_devices_confined();
	test_rootfs_copy_preserves_modes();
	test_rootfs_in_root_symlink();
	test_rootfs_parent_substitution();

	TEST_SUMMARY();
}
