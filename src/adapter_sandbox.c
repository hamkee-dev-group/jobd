#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/stat.h>

#include <linux/capability.h>

#include "jobd.h"

int job_sandbox_check_caps(char *errmsg, size_t errmsg_sz)
{
	if (geteuid() != 0) {
		snprintf(errmsg, errmsg_sz,
		         "jobd must run as root to create namespaces and "
		         "cgroups (euid=%u)", (unsigned)geteuid());
		return -1;
	}

	if (prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN, 0, 0, 0) != 1) {
		snprintf(errmsg, errmsg_sz,
		         "CAP_SYS_ADMIN is not in the bounding set");
		return -1;
	}

	static const char *ns[] = {
		"/proc/self/ns/mnt", "/proc/self/ns/pid", "/proc/self/ns/uts",
		"/proc/self/ns/net", "/proc/self/ns/ipc", NULL
	};
	for (int i = 0; ns[i]; i++) {
		if (access(ns[i], F_OK) != 0) {
			snprintf(errmsg, errmsg_sz,
			         "namespace support missing: %s", ns[i]);
			return -1;
		}
	}

	snprintf(errmsg, errmsg_sz, "sandbox capabilities ok");
	return 0;
}
