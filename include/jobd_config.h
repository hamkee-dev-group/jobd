#ifndef JOBD_CONFIG_H
#define JOBD_CONFIG_H

#include <stddef.h>
#include <sys/types.h>

enum jobd_component {
	JOBD_COMP_CGROUPD = 0,
	JOBD_COMP_CGROUPCTL,
	JOBD_COMP_OVERLAYD,
	JOBD_COMP_SANDBOX,
	JOBD_COMP_LANDLOCKD,
	JOBD_COMP_FANOTIFYD,
	JOBD_COMP_MEMFDBUS,
	JOBD_COMP_IOURINGD,
	JOBD_COMP_JOB_INIT,
	JOBD_COMP_JOB_NETD,
	JOBD_COMP_LANDLOCK_HELPER,
	JOBD_COMP__COUNT
};

#define JOBD_PATH_MAX 512

struct jobd_paths {
	char socket_path[108];
	char runtime_dir[JOBD_PATH_MAX];
	char state_dir[JOBD_PATH_MAX];
	char jobs_dir[JOBD_PATH_MAX];
	char overlay_dir[JOBD_PATH_MAX];
	char cgroup_sock[JOBD_PATH_MAX];
	char cgroup_root[JOBD_PATH_MAX];
	char cgroup_log_dir[JOBD_PATH_MAX];
	char config_file[JOBD_PATH_MAX];
};

struct jobd_access {
	uid_t allow_uid[16];
	int   allow_uid_count;
	gid_t allow_gid[16];
	int   allow_gid_count;
};

struct jobd_features {
	int allow_iouring;
	int allow_network;
	int allow_fanotify;
	int allow_memfd;
};

void jobd_config_init(void);

int  jobd_config_load_file(const char *path, char *err, size_t err_sz);

int  jobd_config_set(const char *key, const char *value,
                       char *err, size_t err_sz);

const struct jobd_paths  *jobd_paths(void);
const struct jobd_access *jobd_access(void);

const struct jobd_features *jobd_features(void);

const char *jobd_component_name(enum jobd_component c);

const char *jobd_component_path(enum jobd_component c);

void jobd_component_search_desc(char *out, size_t out_sz);

int jobd_job_dir(const char *job_id, char *out, size_t out_sz);
int jobd_job_subdir(const char *job_id, const char *sub,
                      char *out, size_t out_sz);
int jobd_job_state_dir(const char *job_id, char *out, size_t out_sz);

#endif
