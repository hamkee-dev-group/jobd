#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "jobd.h"

static int require_component(enum jobd_component c,
                             char *errmsg, size_t errmsg_sz)
{
	const char *path = jobd_component_path(c);
	const char *name = jobd_component_name(c);

	if (!path) {
		char search[1024];
		jobd_component_search_desc(search, sizeof(search));
		snprintf(errmsg, errmsg_sz,
		         "%s not found; searched %s (set it with JOBD_%s, a "
		         "config entry, or --component %s=PATH)",
		         name, search, name, name);
		return -1;
	}

	struct stat st;
	if (stat(path, &st) != 0) {
		snprintf(errmsg, errmsg_sz, "%s: %s: %s", name, path,
		         strerror(errno));
		return -1;
	}
	if (!S_ISREG(st.st_mode) || access(path, X_OK) != 0) {
		snprintf(errmsg, errmsg_sz, "%s is not an executable file: %s",
		         name, path);
		return -1;
	}

	return 0;
}

int job_preflight(const struct job *job, char *errmsg, size_t errmsg_sz)
{

	if (job_sandbox_check_caps(errmsg, errmsg_sz) != 0)
		return -1;

	if (job_kernel_landlock_abi() < 1) {
		snprintf(errmsg, errmsg_sz,
		         "the kernel does not support Landlock; refusing to run "
		         "a job that would be unconfined");
		return -1;
	}
	if (!job_kernel_seccomp_available()) {
		snprintf(errmsg, errmsg_sz,
		         "the kernel does not support seccomp; refusing to run "
		         "a job without syscall filtering");
		return -1;
	}

	static const enum jobd_component required[] = {
		JOBD_COMP_SANDBOX,
		JOBD_COMP_LANDLOCKD,
		JOBD_COMP_CGROUPCTL,
		JOBD_COMP_JOB_INIT,

		JOBD_COMP_OVERLAYD,
	};

	for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
		if (require_component(required[i], errmsg, errmsg_sz) != 0)
			return -1;
	}

	if (job->fanotify_mode != JOBD_FANOTIFY_OFF &&
	    require_component(JOBD_COMP_FANOTIFYD, errmsg, errmsg_sz) != 0)
		return -1;

	if (job->memfd_input_count > 0 &&
	    require_component(JOBD_COMP_MEMFDBUS, errmsg, errmsg_sz) != 0)
		return -1;

	if (job->iouring_enabled &&
	    require_component(JOBD_COMP_IOURINGD, errmsg, errmsg_sz) != 0)
		return -1;

	snprintf(errmsg, errmsg_sz, "preflight ok");
	return 0;
}
