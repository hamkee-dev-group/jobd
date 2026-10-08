#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/openat2.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>

#include "jobd.h"

/*
 * Resolves `path` the way the sandboxed process will: symlinks and ".."
 * are confined to root_fd, so the result is a directory inside the job
 * root even if path components are swapped while staging runs.
 */
static int open_subdir(int root_fd, const char *path)
{
	struct open_how how = {
		.flags   = O_RDONLY | O_DIRECTORY | O_CLOEXEC,
		.resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
	};
	return (int)syscall(SYS_openat2, root_fd, path, &how, sizeof(how));
}

/* Opens `rel` below root_fd, creating missing directories on the way.
 * `rel` is truncated at the failing component when an error is reported. */
static int open_dir_in_root(int root_fd, char *rel, char *err, size_t err_sz)
{
	int dfd = open_subdir(root_fd, ".");
	if (dfd < 0) {
		snprintf(err, err_sz, "cannot reopen the job root: %s",
		         strerror(errno));
		return -1;
	}

	while (*rel == '/')
		rel++;

	for (char *p = rel; *p; ) {
		char *end = strchrnul(p, '/');
		char saved = *end;
		*end = '\0';

		int next = open_subdir(root_fd, rel);
		if (next < 0 && errno == ENOENT) {
			if (mkdirat(dfd, p, 0755) != 0 && errno != EEXIST) {
				snprintf(err, err_sz,
				         "cannot create %s in the job root: %s",
				         rel, strerror(errno));
				close(dfd);
				return -1;
			}
			next = open_subdir(root_fd, rel);
		}
		if (next < 0) {
			snprintf(err, err_sz,
			         "cannot open %s in the job root: %s",
			         rel, strerror(errno));
			close(dfd);
			return -1;
		}
		close(dfd);
		dfd = next;
		*end = saved;
		p = saved ? end + 1 : end;
	}
	return dfd;
}

static int open_source(const char *src, mode_t *mode, char *err, size_t err_sz)
{
	int in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0) {
		snprintf(err, err_sz, "cannot open %s: %s", src,
		         strerror(errno));
		return -1;
	}

	struct stat st;
	if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode)) {
		snprintf(err, err_sz, "%s is not a regular file", src);
		close(in);
		return -1;
	}
	*mode = st.st_mode & 0777;
	return in;
}

static int stage_fd(int root_fd, int in, mode_t mode, const char *inside,
                    char *err, size_t err_sz)
{
	char rel[JOBD_PATH_LEN_LONG];
	int n = snprintf(rel, sizeof(rel), "%s", inside);
	if (n < 0 || (size_t)n >= sizeof(rel)) {
		snprintf(err, err_sz, "job root path too long");
		return -1;
	}

	char *name = rel, *dir = rel + n;
	char *slash = strrchr(rel, '/');
	if (slash) {
		*slash = '\0';
		dir = rel;
		name = slash + 1;
	}
	if (!*name) {
		snprintf(err, err_sz, "%s is not a file path", inside);
		return -1;
	}

	int dfd = open_dir_in_root(root_fd, dir, err, err_sz);
	if (dfd < 0)
		return -1;

	/* Whatever sits there now may be linked to a file outside the root,
	 * so it is replaced by a fresh inode rather than opened. */
	if (unlinkat(dfd, name, 0) != 0 && errno != ENOENT) {
		snprintf(err, err_sz, "cannot replace %s in the job root: %s",
		         inside, strerror(errno));
		close(dfd);
		return -1;
	}
	int out = openat(dfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
	                 mode);
	close(dfd);
	if (out < 0) {
		snprintf(err, err_sz, "cannot create %s in the job root: %s",
		         inside, strerror(errno));
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

	if (rc == 0 && fchmod(out, mode) != 0)
		rc = -1;
	if (rc != 0)
		snprintf(err, err_sz, "cannot write %s in the job root: %s",
		         inside, strerror(errno));

	close(out);
	return rc;
}

/* Returns 1 when an optional source is unusable. Failures inside the job
 * root return -1 and are fatal even for optional files. */
static int copy_into_root(int root_fd, const char *src, const char *inside,
                          int required, char *err, size_t err_sz)
{
	mode_t mode;
	int in = open_source(src, &mode, err, err_sz);
	if (in < 0) {
		if (required)
			return -1;
		jobd_log("rootfs: could not stage %s: %s", inside, err);
		return 1;
	}

	int rc = stage_fd(root_fd, in, mode, inside, err, err_sz);
	close(in);
	return rc;
}

static int stage_deps(int root_fd, const char *binary,
                      char *errmsg, size_t errmsg_sz)
{
	struct job_elf_deps deps;
	char err[256];

	if (job_elf_resolve_deps(binary, &deps, err, sizeof(err)) != 0) {

		jobd_log("rootfs: dependency scan of %s: %s", binary, err);
		return 0;
	}

	for (int i = 0; i < deps.count; i++) {
		if (copy_into_root(root_fd, deps.paths[i], deps.paths[i], 0,
		                   errmsg, errmsg_sz) < 0)
			return -1;
	}
	return 0;
}

static int stage_binary(int root_fd, const char *binary,
                        char *errmsg, size_t errmsg_sz)
{
	if (copy_into_root(root_fd, binary, binary, 1, errmsg, errmsg_sz) != 0)
		return -1;
	return stage_deps(root_fd, binary, errmsg, errmsg_sz);
}

static int stage_component_as(int root_fd, const char *src,
                              const char *inside, int required,
                              char *errmsg, size_t errmsg_sz)
{
	int rc = copy_into_root(root_fd, src, inside, required,
	                        errmsg, errmsg_sz);
	if (rc != 0)
		return rc < 0 ? -1 : 0;
	return stage_deps(root_fd, src, errmsg, errmsg_sz);
}

static int make_devices(int root_fd, char *errmsg, size_t errmsg_sz)
{
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

	char rel[] = "dev";
	int dev_fd = open_dir_in_root(root_fd, rel, errmsg, errmsg_sz);
	if (dev_fd < 0)
		return -1;

	for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++) {
		unlinkat(dev_fd, devices[i].name, 0);

		/* The node gets its final mode at creation, so no chmod can
		 * ever be applied to a substituted inode. */
		mode_t old = umask(0);
		int rc = mknodat(dev_fd, devices[i].name,
		                 S_IFCHR | devices[i].mode,
		                 makedev(devices[i].major, devices[i].minor));
		umask(old);
		if (rc != 0)
			jobd_log("rootfs: cannot create /dev/%s: %s",
			           devices[i].name, strerror(errno));
	}

	close(dev_fd);
	return 0;
}

static int prepare_in_root(const struct job *job, int root_fd,
                           char *errmsg, size_t errmsg_sz)
{
	static const char *inroot_dirs[] = {
		"run/jobd", "workspace", "export", "tmp", "proc", "dev",
		"usr/bin", "usr/lib", "usr/lib64", "lib", "lib64", "bin", "etc",
		NULL
	};
	for (int i = 0; inroot_dirs[i]; i++) {
		char rel[JOBD_PATH_LEN_LONG];
		snprintf(rel, sizeof(rel), "%s", inroot_dirs[i]);
		int fd = open_dir_in_root(root_fd, rel, errmsg, errmsg_sz);
		if (fd < 0)
			return -1;
		close(fd);
	}

	if (make_devices(root_fd, errmsg, errmsg_sz) != 0)
		return -1;

	if (stage_binary(root_fd, job->argv_buf, errmsg, errmsg_sz) != 0)
		return -1;

	const char *landlockd = jobd_component_path(JOBD_COMP_LANDLOCKD);
	if (!landlockd) {
		snprintf(errmsg, errmsg_sz,
		         "landlockd not found; cannot stage the job root");
		return -1;
	}

	if (stage_component_as(root_fd, landlockd, "/usr/bin/landlockd", 1,
	                       errmsg, errmsg_sz) != 0)
		return -1;

	const char *helper = jobd_component_path(JOBD_COMP_LANDLOCK_HELPER);
	if (helper &&
	    stage_component_as(root_fd, helper,
	                       "/usr/bin/landlockd-policy-helper", 0,
	                       errmsg, errmsg_sz) != 0)
		return -1;

	if (job->memfd_input_count > 0) {
		const char *mb = jobd_component_path(JOBD_COMP_MEMFDBUS);
		if (!mb) {
			snprintf(errmsg, errmsg_sz,
			         "memfdbus not found; cannot stage the client");
			return -1;
		}
		if (stage_component_as(root_fd, mb, "/usr/bin/memfdbus", 1,
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
		if (stage_component_as(root_fd, netd, "/usr/bin/job-netd", 1,
		                       errmsg, errmsg_sz) != 0)
			return -1;
	}

	return 0;
}

int job_rootfs_prepare(struct job *job, char *errmsg, size_t errmsg_sz)
{
	const char *root = job->root_path;

	if (mkdir(root, 0755) != 0 && errno != EEXIST) {
		snprintf(errmsg, errmsg_sz, "cannot create %s: %s",
		         root, strerror(errno));
		return -1;
	}

	/* The daemon-owned parent is trusted; from here on every operation
	 * is relative to this descriptor rather than to the root's name. */
	int root_fd = open(root,
	                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (root_fd < 0) {
		snprintf(errmsg, errmsg_sz, "cannot open %s: %s",
		         root, strerror(errno));
		return -1;
	}

	int rc = prepare_in_root(job, root_fd, errmsg, errmsg_sz);
	close(root_fd);
	if (rc == 0)
		snprintf(errmsg, errmsg_sz, "rootfs prepared at %s", root);
	return rc;
}
