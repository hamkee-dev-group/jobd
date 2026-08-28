#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "jobd.h"

static int mkdir_p(const char *path)
{
	char tmp[JOBD_PATH_LEN_LONG];
	int n = snprintf(tmp, sizeof(tmp), "%s", path);
	if (n < 0 || (size_t)n >= sizeof(tmp))
		return -1;

	size_t len = strlen(tmp);
	while (len > 1 && tmp[len - 1] == '/')
		tmp[--len] = '\0';

	for (char *p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, 0755) < 0 && errno != EEXIST) {
			*p = '/';
			return -1;
		}
		*p = '/';
	}

	if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
		return -1;
	return 0;
}

static int parent_dir(const char *path, char *out, size_t out_sz)
{
	int n = snprintf(out, out_sz, "%s", path);
	if (n < 0 || (size_t)n >= out_sz)
		return -1;
	char *slash = strrchr(out, '/');
	if (!slash)
		return -1;
	if (slash == out)
		out[1] = '\0';
	else
		*slash = '\0';
	return 0;
}

static int copy_file(const char *src, const char *dst)
{
	int in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -1;

	struct stat st;
	if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode)) {
		close(in);
		return -1;
	}

	char dir[JOBD_PATH_LEN_LONG];
	if (parent_dir(dst, dir, sizeof(dir)) == 0)
		mkdir_p(dir);

	mode_t mode = st.st_mode & 0777;
	int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
	               mode);
	if (out < 0) {
		close(in);
		return -1;
	}

	char buf[65536];
	ssize_t got;
	int rc = 0;
	while ((got = read(in, buf, sizeof(buf))) > 0) {
		ssize_t off = 0;
		while (off < got) {
			ssize_t w = write(out, buf + off, (size_t)(got - off));
			if (w < 0) {
				if (errno == EINTR)
					continue;
				rc = -1;
				break;
			}
			off += w;
		}
		if (rc != 0)
			break;
	}
	if (got < 0)
		rc = -1;

	if (fchmod(out, mode) != 0 && rc == 0)
		rc = -1;

	close(in);
	close(out);
	return rc;
}

static int copy_into_root(const char *root, const char *src)
{
	char dst[JOBD_PATH_LEN_LONG];
	int n = snprintf(dst, sizeof(dst), "%s%s", root, src);
	if (n < 0 || (size_t)n >= sizeof(dst))
		return -1;
	return copy_file(src, dst);
}

static void stage_deps(const char *root, const char *binary)
{
	struct job_elf_deps deps;
	char err[256];

	if (job_elf_resolve_deps(binary, &deps, err, sizeof(err)) != 0) {

		jobd_log("rootfs: dependency scan of %s: %s", binary, err);
		return;
	}

	for (int i = 0; i < deps.count; i++) {
		if (copy_into_root(root, deps.paths[i]) != 0)
			jobd_log("rootfs: could not stage %s", deps.paths[i]);
	}
}

static int stage_binary(const char *root, const char *binary,
                        char *errmsg, size_t errmsg_sz)
{
	if (copy_into_root(root, binary) != 0) {
		snprintf(errmsg, errmsg_sz, "cannot stage %s into the job root",
		         binary);
		return -1;
	}
	stage_deps(root, binary);
	return 0;
}

static int stage_component_as(const char *root, const char *src,
                              const char *inside, int required,
                              char *errmsg, size_t errmsg_sz)
{
	char dst[JOBD_PATH_LEN_LONG];
	int n = snprintf(dst, sizeof(dst), "%s%s", root, inside);
	if (n < 0 || (size_t)n >= sizeof(dst)) {
		snprintf(errmsg, errmsg_sz, "job root path too long");
		return required ? -1 : 0;
	}

	if (copy_file(src, dst) != 0) {
		if (required) {
			snprintf(errmsg, errmsg_sz,
			         "cannot stage %s into the job root", inside);
			return -1;
		}
		jobd_log("rootfs: could not stage %s", inside);
		return 0;
	}

	stage_deps(root, src);
	return 0;
}

int job_rootfs_prepare(struct job *job, char *errmsg, size_t errmsg_sz)
{
	const char *root = job->root_path;

	if (mkdir_p(root) != 0) {
		snprintf(errmsg, errmsg_sz, "cannot create %s: %s",
		         root, strerror(errno));
		return -1;
	}

	static const char *inroot_dirs[] = {
		"run/jobd", "workspace", "export", "tmp", "proc", "dev",
		"usr/bin", "usr/lib", "usr/lib64", "lib", "lib64", "bin", "etc",
		NULL
	};
	for (int i = 0; inroot_dirs[i]; i++) {
		char d[JOBD_PATH_LEN_LONG];
		int n = snprintf(d, sizeof(d), "%s/%s", root, inroot_dirs[i]);
		if (n < 0 || (size_t)n >= sizeof(d))
			continue;
		mkdir_p(d);
	}

	static const struct {
		const char *name;
		mode_t      mode;
		unsigned    major, minor;
	} devices[] = {
		{ "null",    0666, 1, 3 },
		{ "zero",    0666, 1, 5 },
		{ "full",    0666, 1, 7 },
		{ "random",  0666, 1, 8 },
		{ "urandom", 0666, 1, 9 },
		{ "tty",     0666, 5, 0 },
	};

	for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
		char d[JOBD_PATH_LEN_LONG];
		int n = snprintf(d, sizeof(d), "%s/dev/%s", root, devices[i].name);
		if (n < 0 || (size_t)n >= sizeof(d))
			continue;

		unlink(d);
		if (mknod(d, S_IFCHR | devices[i].mode,
		          makedev(devices[i].major, devices[i].minor)) != 0) {
			jobd_log("rootfs: cannot create /dev/%s: %s",
			           devices[i].name, strerror(errno));
			continue;
		}

		if (chmod(d, devices[i].mode) != 0)
			jobd_log("rootfs: cannot chmod /dev/%s", devices[i].name);
	}

	if (stage_binary(root, job->argv_buf, errmsg, errmsg_sz) != 0)
		return -1;

	const char *landlockd = jobd_component_path(JOBD_COMP_LANDLOCKD);
	if (!landlockd) {
		snprintf(errmsg, errmsg_sz,
		         "landlockd not found; cannot stage the job root");
		return -1;
	}

	if (stage_component_as(root, landlockd, "/usr/bin/landlockd", 1,
	                       errmsg, errmsg_sz) != 0)
		return -1;

	const char *helper = jobd_component_path(JOBD_COMP_LANDLOCK_HELPER);
	if (helper)
		stage_component_as(root, helper, "/usr/bin/landlockd-policy-helper",
		                   0, errmsg, errmsg_sz);

	if (job->memfd_input_count > 0) {
		const char *mb = jobd_component_path(JOBD_COMP_MEMFDBUS);
		if (!mb) {
			snprintf(errmsg, errmsg_sz,
			         "memfdbus not found; cannot stage the client");
			return -1;
		}
		if (stage_component_as(root, mb, "/usr/bin/memfdbus", 1,
		                       errmsg, errmsg_sz) != 0)
			return -1;
	}

	if (job->network_mode == JOBD_NETWORK_BROKERED) {
		const char *netd = jobd_component_path(JOBD_COMP_JOB_NETD);
		if (!netd) {
			snprintf(errmsg, errmsg_sz,
			         "job-netd not found; cannot stage the relay");
			return -1;
		}
		if (stage_component_as(root, netd, "/usr/bin/job-netd", 1,
		                       errmsg, errmsg_sz) != 0)
			return -1;
	}

	snprintf(errmsg, errmsg_sz, "rootfs prepared at %s", root);
	return 0;
}
