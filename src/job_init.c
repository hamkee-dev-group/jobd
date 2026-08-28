#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <net/if.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#define EXIT_ISOLATION 125

static void fail(const char *what)
{
	fprintf(stderr, "job-init: %s failed: %s\n", what, strerror(errno));
	fprintf(stderr, "job-init: refusing to run the workload without the "
	                "requested isolation\n");
	_exit(EXIT_ISOLATION);
}

static void close_inherited_fds(void)
{
#if defined(__NR_close_range)
	if (syscall(__NR_close_range, 3, ~0U, 0) == 0)
		return;
#endif
	DIR *d = opendir("/proc/self/fd");
	if (d) {
		int dfd = dirfd(d);
		struct dirent *ent;
		while ((ent = readdir(d))) {
			if (ent->d_name[0] < '0' || ent->d_name[0] > '9')
				continue;
			int fd = atoi(ent->d_name);
			if (fd > 2 && fd != dfd)
				close(fd);
		}
		closedir(d);
		return;
	}

	long max_fd = sysconf(_SC_OPEN_MAX);
	if (max_fd < 0 || max_fd > 1048576)
		max_fd = 1048576;
	for (int fd = 3; fd < (int)max_fd; fd++)
		close(fd);
}

static int loopback_up(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) != 0) {
		close(fd);
		return -1;
	}

	ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) != 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static void usage(void)
{
	fprintf(stderr,
	        "usage: job-init --root DIR [--network none|brokered] "
	        "-- COMMAND [ARGS...]\n");
}

int main(int argc, char *argv[])
{
	const char *root    = NULL;
	const char *network = "none";
	int child_start = -1;

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			child_start = i + 1;
			break;
		}
		if (strcmp(argv[i], "--root") == 0 && i + 1 < argc) {
			root = argv[++i];
		} else if (strcmp(argv[i], "--network") == 0 && i + 1 < argc) {
			network = argv[++i];
		} else {
			fprintf(stderr, "job-init: unexpected argument: %s\n",
			        argv[i]);
			usage();
			return 1;
		}
	}

	if (!root) {
		fprintf(stderr, "job-init: --root is required\n");
		usage();
		return 1;
	}
	if (child_start < 0 || child_start >= argc) {
		fprintf(stderr, "job-init: missing child command after --\n");
		usage();
		return 1;
	}

	if (strcmp(network, "none") != 0 && strcmp(network, "brokered") != 0) {
		fprintf(stderr, "job-init: unsupported network mode: %s\n",
		        network);
		return 1;
	}

	if (chdir(root) != 0) {
		fprintf(stderr, "job-init: chdir(%s) failed: %s\n",
		        root, strerror(errno));
		return 1;
	}

	if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0)
		fail("prctl(PR_SET_PDEATHSIG)");

	if (unshare(CLONE_NEWNS) != 0)
		fail("unshare(CLONE_NEWNS)");
	if (mount(NULL, "/", NULL, MS_PRIVATE | MS_REC, NULL) != 0)
		fail("mount(/, MS_PRIVATE|MS_REC)");

	if (unshare(CLONE_NEWNET) != 0)
		fail("unshare(CLONE_NEWNET)");
	if (unshare(CLONE_NEWIPC) != 0)
		fail("unshare(CLONE_NEWIPC)");

	if (loopback_up() != 0)
		fail("bringing up loopback");

	close_inherited_fds();

	execv(argv[child_start], &argv[child_start]);

	fprintf(stderr, "job-init: exec(%s) failed: %s\n",
	        argv[child_start], strerror(errno));
	return 127;
}
