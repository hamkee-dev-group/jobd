#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "jobd.h"

#define OVERLAY_TIMEOUT_MS 30000

#define JOBD_BASE_LAYER "jobd-base"

static int overlay_run(char *const av[], struct job_spawn_out *out,
                       char *errmsg, size_t errmsg_sz)
{
	struct job_spawn_out local;
	struct job_spawn_out *o = out ? out : &local;

	int rc = job_spawn(av, NULL, NULL, OVERLAY_TIMEOUT_MS, o);
	if (rc != 0) {
		snprintf(errmsg, errmsg_sz, "%s",
		         o->stderr_buf[0] ? o->stderr_buf :
		         (o->stdout_buf[0] ? o->stdout_buf : "overlayd failed"));
		return -1;
	}
	return 0;
}

static const char *overlay_bin(char *errmsg, size_t errmsg_sz)
{
	const char *bin = jobd_component_path(JOBD_COMP_OVERLAYD);
	if (!bin)
		snprintf(errmsg, errmsg_sz, "overlayd not found");
	return bin;
}

int job_overlay_ensure_store(char *errmsg, size_t errmsg_sz)
{
	const char *bin = overlay_bin(errmsg, errmsg_sz);
	if (!bin)
		return -1;

	const char *store = jobd_paths()->overlay_dir;
	if (mkdir(store, 0700) != 0 && errno != EEXIST) {
		snprintf(errmsg, errmsg_sz, "cannot create %s: %s", store,
		         strerror(errno));
		return -1;
	}

	char *init_av[] = { (char *)bin, (char *)"--root", (char *)store,
	                    (char *)"init", NULL };
	struct job_spawn_out out;
	if (overlay_run(init_av, &out, errmsg, errmsg_sz) != 0) {

		char marker[JOBD_PATH_LEN_LONG];
		int n = snprintf(marker, sizeof(marker), "%s/layers", store);
		struct stat st;
		if (n < 0 || (size_t)n >= sizeof(marker) ||
		    stat(marker, &st) != 0 || !S_ISDIR(st.st_mode)) {
			snprintf(errmsg, errmsg_sz,
			         "cannot initialise the overlay store at %s", store);
			return -1;
		}
	}

	char *layer_av[] = { (char *)bin, (char *)"--root", (char *)store,
	                     (char *)"layer", (char *)"create",
	                     (char *)JOBD_BASE_LAYER, NULL };
	overlay_run(layer_av, &out, errmsg, errmsg_sz);

	snprintf(errmsg, errmsg_sz, "overlay store ready at %s", store);
	return 0;
}

int job_overlay_layer_exists(const char *name)
{
	char errmsg[256];
	const char *bin = overlay_bin(errmsg, sizeof(errmsg));
	if (!bin)
		return 0;

	const char *store = jobd_paths()->overlay_dir;
	char *av[] = { (char *)bin, (char *)"--root", (char *)store,
	               (char *)"layer", (char *)"list", NULL };

	struct job_spawn_out out;
	if (job_spawn(av, NULL, NULL, OVERLAY_TIMEOUT_MS, &out) != 0)
		return 0;

	const char *p = out.stdout_buf;
	size_t namelen = strlen(name);

	while (*p) {
		const char *eol = strchr(p, '\n');
		size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
		const char *tab = memchr(p, '\t', linelen);
		size_t field = tab ? (size_t)(tab - p) : linelen;

		if (field == namelen && memcmp(p, name, namelen) == 0)
			return 1;

		if (!eol)
			break;
		p = eol + 1;
	}

	return 0;
}

int job_overlay_create_ws(const struct job *job,
                            char *errmsg, size_t errmsg_sz)
{
	const char *bin = overlay_bin(errmsg, errmsg_sz);
	if (!bin)
		return -1;

	const char *store = jobd_paths()->overlay_dir;

	if (mkdir(job->root_path, 0755) != 0 && errno != EEXIST) {
		snprintf(errmsg, errmsg_sz, "cannot create the mountpoint: %s",
		         strerror(errno));
		return -1;
	}

	char *av[16 + JOBD_MAX_LAYERS * 2];
	int ac = 0;
	av[ac++] = (char *)bin;
	av[ac++] = (char *)"--root";
	av[ac++] = (char *)store;
	av[ac++] = (char *)"ws";
	av[ac++] = (char *)"create";
	av[ac++] = (char *)job->id;

	if (job->layer_count == 0) {
		av[ac++] = (char *)"-l";
		av[ac++] = (char *)JOBD_BASE_LAYER;
	} else {
		for (uint32_t i = 0; i < job->layer_count; i++) {
			if (!job_overlay_layer_exists(job->layers[i])) {
				snprintf(errmsg, errmsg_sz,
				         "layer '%s' does not exist in %s",
				         job->layers[i], store);
				return -1;
			}
			av[ac++] = (char *)"-l";
			av[ac++] = (char *)job->layers[i];
		}
	}

	av[ac++] = (char *)"-m";
	av[ac++] = (char *)job->root_path;
	av[ac] = NULL;

	struct job_spawn_out out;
	if (overlay_run(av, &out, errmsg, errmsg_sz) != 0) {
		snprintf(errmsg, errmsg_sz,
		         "overlayd could not create the workspace: %s",
		         out.stderr_buf[0] ? out.stderr_buf : "unknown error");
		return -1;
	}

	struct stat st_root, st_parent;
	char parent[JOBD_PATH_LEN_LONG];
	int n = snprintf(parent, sizeof(parent), "%s/..", job->root_path);
	if (n > 0 && (size_t)n < sizeof(parent) &&
	    stat(job->root_path, &st_root) == 0 &&
	    stat(parent, &st_parent) == 0 &&
	    st_root.st_dev == st_parent.st_dev) {
		snprintf(errmsg, errmsg_sz,
		         "overlayd reported success but %s is not a mount point",
		         job->root_path);
		return -1;
	}

	snprintf(errmsg, errmsg_sz, "overlay workspace mounted at %s",
	         job->root_path);
	return 0;
}

void job_overlay_remove_ws(const char *job_id)
{
	char errmsg[256];
	const char *bin = overlay_bin(errmsg, sizeof(errmsg));
	if (!bin)
		return;

	const char *store = jobd_paths()->overlay_dir;
	char *av[] = { (char *)bin, (char *)"--root", (char *)store,
	               (char *)"ws", (char *)"rm", (char *)job_id,
	               (char *)"--force", NULL };

	struct job_spawn_out out;
	if (job_spawn(av, NULL, NULL, OVERLAY_TIMEOUT_MS, &out) != 0)
		jobd_log("overlay: could not remove workspace %s: %s", job_id,
		           out.stderr_buf[0] ? out.stderr_buf : "unknown error");
}
