#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/vfs.h>

#include "jobd.h"

#include <sys/syscall.h>

#define CGROUP2_SUPER_MAGIC 0x63677270

#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

int job_kernel_landlock_abi(void)
{
#ifdef __NR_landlock_create_ruleset
	long abi = syscall(__NR_landlock_create_ruleset, NULL, 0,
	                   LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0)
		return -1;
	return (int)abi;
#else
	return -1;
#endif
}

int job_kernel_seccomp_available(void)
{
#ifdef __NR_seccomp

	errno = 0;
	long rc = syscall(__NR_seccomp, 2 , 0, NULL);
	if (rc == 0)
		return 1;
	return errno == EFAULT;
#else
	return 0;
#endif
}

static int check_cgroup_v2(void)
{
	struct statfs sfs;
	if (statfs("/sys/fs/cgroup", &sfs) != 0)
		return 0;
	return sfs.f_type == CGROUP2_SUPER_MAGIC;
}

static int check_overlayfs(void)
{
	int fd = open("/proc/filesystems", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;

	char buf[4096];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	return strstr(buf, "overlay") != NULL;
}

static int check_namespaces(void)
{
	static const char *paths[] = {
		"/proc/self/ns/mnt", "/proc/self/ns/pid", "/proc/self/ns/uts",
		"/proc/self/ns/net", "/proc/self/ns/ipc", NULL
	};
	for (int i = 0; paths[i]; i++) {
		struct stat st;
		if (lstat(paths[i], &st) != 0)
			return 0;
	}
	return 1;
}

static int check_memfd_sealing(void)
{
	int fd = memfd_create("jobd-doctor", MFD_ALLOW_SEALING);
	if (fd < 0)
		return 0;
	close(fd);
	return 1;
}

static int check_io_uring(void)
{

	return access("/proc/sys/kernel/io_uring_disabled", F_OK) == 0;
}

static int check_dir_writable(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0)
		return 0;
	if (!S_ISDIR(st.st_mode))
		return 0;
	return access(path, W_OK | X_OK) == 0;
}

static void row(struct agd_buf *b, const char *name, int ok, int *all_ok,
                int required)
{
	const char *status;
	if (ok)
		status = "PASS";
	else if (required) {
		status = "FAIL";
		if (all_ok)
			*all_ok = 0;
	} else {
		status = "WARN";
	}
	agd_buf_addf(b, "  %-22s %s\n", name, status);
}

int jobd_doctor(char *output, size_t output_sz)
{
	struct agd_buf b;
	agd_buf_init(&b, output, output_sz);

	int all_ok = 1;

	agd_buf_adds(&b, "=== jobd doctor ===\n");

	struct utsname uts;
	if (uname(&uts) == 0)
		agd_buf_addf(&b, "kernel: %s %s %s\n",
		             uts.sysname, uts.release, uts.machine);
	agd_buf_addf(&b, "running as: uid=%u euid=%u\n",
	             (unsigned)getuid(), (unsigned)geteuid());

	agd_buf_adds(&b, "\n=== kernel features ===\n");
	row(&b, "cgroup v2", check_cgroup_v2(), &all_ok, 1);
	row(&b, "overlayfs", check_overlayfs(), &all_ok, 1);
	row(&b, "namespaces", check_namespaces(), &all_ok, 1);
	int abi = job_kernel_landlock_abi();
	if (abi > 0)
		agd_buf_addf(&b, "  %-22s PASS  (ABI %d)\n", "Landlock", abi);
	else {
		agd_buf_addf(&b, "  %-22s FAIL  not available\n", "Landlock");
		all_ok = 0;
	}
	row(&b, "seccomp", job_kernel_seccomp_available(), &all_ok, 1);
	row(&b, "memfd sealing", check_memfd_sealing(), &all_ok, 0);
	row(&b, "io_uring", check_io_uring(), &all_ok, 0);
	row(&b, "fanotify",
	    access("/proc/sys/fs/fanotify/max_marks", R_OK) == 0, &all_ok, 0);

	agd_buf_adds(&b, "\n=== components ===\n");
	{
		char search[1024];
		jobd_component_search_desc(search, sizeof(search));
		agd_buf_addf(&b, "search path: %s\n\n", search);
	}

	static const struct {
		enum jobd_component c;
		int required;
	} comps[] = {
		{ JOBD_COMP_CGROUPCTL,       1 },
		{ JOBD_COMP_CGROUPD,         0 },
		{ JOBD_COMP_SANDBOX,         1 },
		{ JOBD_COMP_LANDLOCKD,       1 },
		{ JOBD_COMP_JOB_INIT,      1 },
		{ JOBD_COMP_OVERLAYD,        1 },
		{ JOBD_COMP_FANOTIFYD,       0 },
		{ JOBD_COMP_MEMFDBUS,        0 },
		{ JOBD_COMP_IOURINGD,        0 },
		{ JOBD_COMP_LANDLOCK_HELPER, 0 },
	};

	for (size_t i = 0; i < sizeof(comps) / sizeof(comps[0]); i++) {
		const char *name = jobd_component_name(comps[i].c);
		const char *path = jobd_component_path(comps[i].c);

		if (path) {
			agd_buf_addf(&b, "  %-22s PASS  %s\n", name, path);
		} else if (comps[i].required) {
			agd_buf_addf(&b, "  %-22s FAIL  not found\n", name);
			all_ok = 0;
		} else {
			agd_buf_addf(&b, "  %-22s WARN  not found (optional)\n", name);
		}
	}

	agd_buf_adds(&b, "\n=== paths ===\n");
	{
		const struct jobd_paths *p = jobd_paths();
		agd_buf_addf(&b, "  %-22s %s\n", "socket", p->socket_path);
		agd_buf_addf(&b, "  %-22s %s\n", "runtime_dir", p->runtime_dir);
		agd_buf_addf(&b, "  %-22s %s\n", "state_dir", p->state_dir);
		agd_buf_addf(&b, "  %-22s %s\n", "overlay_dir", p->overlay_dir);
		agd_buf_addf(&b, "  %-22s %s\n", "cgroup_sock", p->cgroup_sock);
		agd_buf_addf(&b, "  %-22s %s\n", "cgroup_root", p->cgroup_root);
		agd_buf_addf(&b, "  %-22s %s\n", "config_file", p->config_file);

		row(&b, "runtime_dir writable", check_dir_writable(p->runtime_dir),
		    &all_ok, 1);
		row(&b, "state_dir writable", check_dir_writable(p->state_dir),
		    &all_ok, 0);
	}

	agd_buf_adds(&b, "\n=== optional components ===\n");
	{
		const struct jobd_features *f = jobd_features();
		agd_buf_addf(&b, "  %-22s %s\n", "allow_iouring",
		             f->allow_iouring ? "yes" : "no");
		agd_buf_addf(&b, "  %-22s %s\n", "allow_network",
		             f->allow_network ? "yes" : "no");
		agd_buf_addf(&b, "  %-22s %s\n", "allow_fanotify",
		             f->allow_fanotify ? "yes" : "no");
		agd_buf_addf(&b, "  %-22s %s\n", "allow_memfd",
		             f->allow_memfd ? "yes" : "no");
	}

	agd_buf_addf(&b, "\n=== overall: %s ===\n",
	             all_ok ? "PASS" : "SOME CHECKS FAILED");

	return 0;
}
